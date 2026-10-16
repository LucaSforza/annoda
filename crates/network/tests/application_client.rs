use std::{io::Cursor, sync::Arc, time::Duration};

use annoda_core::{
    AccountKeyStore,
    identity::{DevelopmentIssuer, IdentityIssuer, IssuanceRequest},
    key_store::{AccountKeyStoreError, PortableAccountVault},
    matching::{ContactHandle, ContactService, MatchState},
    protocol::ContentHash,
};
use annoda_intelligence::safety::DeterministicSafetyFixture;
use annoda_network::{
    ManualClock, NodeConfig, PeerNode, SyncBudget, SyncPeerAddress,
    client::{AnnodaClient, ClientConfig},
};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use rusqlite::Connection;
use tempfile::TempDir;

const NOW: u64 = 2_000;

fn jpeg(seed: u8) -> Vec<u8> {
    let pixels = ImageBuffer::from_fn(32, 24, |x, y| {
        Rgb([seed.wrapping_add(x as u8), y as u8, 90])
    });
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(pixels)
        .write_to(&mut output, ImageFormat::Jpeg)
        .expect("encode test photo");
    output.into_inner()
}

#[tokio::test]
async fn public_client_create_import_close_and_reopen_preserves_exact_identity_and_credential() {
    let issuer = DevelopmentIssuer::new().expect("development issuer");
    let issuers = issuer.trusted_issuers();
    let dir = TempDir::new().expect("temporary account directory");
    let account_dir = dir.path().join("account");
    let config = || {
        ClientConfig::new(&account_dir, vec![], issuers.clone())
            .with_clock(Arc::new(ManualClock::new(NOW)))
            .with_sync_budget(annoda_network::SyncBudget {
                max_duration: Duration::from_secs(2),
                ..Default::default()
            })
    };

    let mut alice =
        AnnodaClient::create(config(), b"application-test-passphrase").expect("create account");
    let original = alice.identity_summary().expect("public identity summary");
    assert!(
        alice
            .published_profile()
            .expect("profile lookup before first publication")
            .is_none()
    );
    let credential = issuer
        .issue(IssuanceRequest {
            signing_key: original.signing_public_key,
            encryption_key: original.encryption_public_key.clone(),
            first_name: "Alice".into(),
            age_at_issue: 28,
            issued_at: NOW - 1,
            expires_at: NOW + 3_000,
        })
        .expect("synthetic, explicitly trusted credential");
    alice
        .attach_credential(credential.clone())
        .expect("import credential");

    let vault = PortableAccountVault::new(&account_dir);
    assert!(matches!(
        vault.unlock(b"application-test-passphrase"),
        Err(AccountKeyStoreError::BusyLocked)
    ));
    alice.close();

    let reopened =
        AnnodaClient::open(config(), b"application-test-passphrase").expect("reopen account");
    assert_eq!(reopened.identity_summary().unwrap(), original);
    assert_eq!(reopened.credential().unwrap(), credential);
    reopened.close();

    let zero_budget_config = || {
        ClientConfig::new(&account_dir, vec![], issuers.clone())
            .with_clock(Arc::new(ManualClock::new(NOW)))
            .with_sync_budget(SyncBudget {
                max_mailbox_items: 0,
                ..SyncBudget::default()
            })
    };
    let mut zero_budget = AnnodaClient::open(zero_budget_config(), b"application-test-passphrase")
        .expect("reopen with an exhausted item budget");
    let report = zero_budget
        .sync(Default::default())
        .await
        .expect("zero-item sync completes without network startup");
    assert_eq!(report.status, annoda_network::SyncStatus::BudgetExhausted);
    assert_eq!(report.downloaded_bytes, 0);
    assert_eq!(report.uploaded_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_public_clients_publish_discover_match_share_contacts_and_restart() {
    let issuer = DevelopmentIssuer::new().expect("development issuer");
    let issuers = issuer.trusted_issuers();
    let clock = Arc::new(ManualClock::new(NOW));
    let root = TempDir::new().expect("test root");
    let volunteer_a_dir = root.path().join("volunteer-a");
    let volunteer_b_dir = root.path().join("volunteer-b");
    let volunteer_a = PeerNode::start(
        NodeConfig {
            data_dir: volunteer_a_dir,
            clock: clock.clone(),
            request_timeout: Duration::from_secs(2),
            ..NodeConfig::default()
        },
        issuers.clone(),
    )
    .await
    .expect("volunteer A");
    let address_a = volunteer_a.wait_for_listeners().await.expect("A listener")[0].clone();
    let volunteer_b = PeerNode::start(
        NodeConfig {
            data_dir: volunteer_b_dir,
            clock: clock.clone(),
            request_timeout: Duration::from_secs(2),
            ..NodeConfig::default()
        },
        issuers.clone(),
    )
    .await
    .expect("volunteer B");
    let address_b = volunteer_b.wait_for_listeners().await.expect("B listener")[0].clone();
    let peers = vec![
        SyncPeerAddress {
            peer_id: volunteer_a.peer_id().to_string(),
            address: address_a.to_string(),
        },
        SyncPeerAddress {
            peer_id: volunteer_b.peer_id().to_string(),
            address: address_b.to_string(),
        },
    ];
    let safety = || {
        Arc::new(DeterministicSafetyFixture::new(0.0).expect("fixture"))
            as Arc<dyn annoda_intelligence::safety::PhotoSafetyClassifier>
    };
    let client_config = |name: &str| {
        ClientConfig::new(root.path().join(name), peers.clone(), issuers.clone())
            .with_clock(clock.clone())
            .with_sync_budget(SyncBudget {
                max_duration: Duration::from_secs(15),
                max_mailbox_items: 32,
                ..SyncBudget::default()
            })
            .with_safety_classifier(safety(), true)
    };
    let mut alice = AnnodaClient::create(client_config("alice"), b"alice application passphrase")
        .expect("Alice account");
    let mut bob = AnnodaClient::create(client_config("bob"), b"bob application passphrase")
        .expect("Bob account");
    let alice_identity = alice.identity_summary().expect("Alice public identity");
    let bob_identity = bob.identity_summary().expect("Bob public identity");
    let alice_credential = issuer
        .issue(IssuanceRequest {
            signing_key: alice_identity.signing_public_key,
            encryption_key: alice_identity.encryption_public_key,
            first_name: "Alice".into(),
            age_at_issue: 28,
            issued_at: NOW - 1,
            expires_at: NOW + 10_000,
        })
        .expect("Alice synthetic issuer credential");
    let bob_credential = issuer
        .issue(IssuanceRequest {
            signing_key: bob_identity.signing_public_key,
            encryption_key: bob_identity.encryption_public_key,
            first_name: "Bob".into(),
            age_at_issue: 30,
            issued_at: NOW - 1,
            expires_at: NOW + 10_000,
        })
        .expect("Bob synthetic issuer credential");
    let alice_id = alice_identity.profile_id;
    let bob_id = bob_identity.profile_id;
    alice
        .attach_credential(alice_credential)
        .expect("Alice credential");
    bob.attach_credential(bob_credential)
        .expect("Bob credential");

    let alice_initial_publication = alice
        .publish_profile(vec![jpeg(3), jpeg(60), jpeg(120)])
        .await
        .expect("publish Alice's three photos");
    let initial_profile = alice
        .published_profile()
        .expect("read locally published profile")
        .expect("profile exists after publication");
    assert_eq!(initial_profile.revision, alice_initial_publication.revision);
    assert_eq!(initial_profile.photos.len(), 3);
    let alice_publication = alice
        .publish_profile(vec![jpeg(60), jpeg(3), jpeg(200)])
        .await
        .expect("reorder and replace Alice's photos");
    assert_eq!(
        alice_publication.revision,
        alice_initial_publication.revision + 1
    );
    let updated_profile = alice
        .published_profile()
        .expect("read updated local profile")
        .expect("updated profile exists");
    assert_eq!(updated_profile.revision, alice_publication.revision);
    assert_eq!(updated_profile.photos.len(), 3);
    assert_eq!(
        updated_profile.photos[0].hash,
        initial_profile.photos[1].hash
    );
    assert_eq!(
        updated_profile.photos[1].hash,
        initial_profile.photos[0].hash
    );
    assert!(
        !initial_profile
            .photos
            .iter()
            .any(|old| old.hash == updated_profile.photos[2].hash)
    );
    let bob_publication = bob
        .publish_profile(vec![jpeg(8), jpeg(80), jpeg(160)])
        .await
        .expect("publish Bob's three photos");
    assert_eq!(alice_publication.replicated_peers, 2);
    assert_eq!(bob_publication.replicated_peers, 2);

    let discovered = bob
        .discover(Default::default())
        .await
        .expect("discover Alice without a profile ID");
    let alice_candidate = discovered
        .items
        .iter()
        .find(|candidate| candidate.profile.owner == alice_id)
        .expect("Alice discovered");
    assert_eq!(alice_candidate.profile.revision, alice_publication.revision);
    assert_eq!(
        alice_candidate
            .profile
            .photos
            .iter()
            .map(|photo| photo.hash)
            .collect::<Vec<_>>(),
        updated_profile
            .photos
            .iter()
            .map(|photo| photo.hash)
            .collect::<Vec<_>>()
    );
    let alice_photo_hash = alice_candidate.profile.photos[0].hash;
    let fetched = bob
        .fetch_photo(alice_id, alice_photo_hash)
        .await
        .expect("validated photo download");
    assert_eq!(ContentHash::digest(&fetched.bytes), alice_photo_hash);
    let alice_finds_bob = alice
        .discover(Default::default())
        .await
        .expect("Alice discovers Bob without a profile ID");
    let bob_candidate = alice_finds_bob
        .items
        .iter()
        .find(|candidate| candidate.profile.owner == bob_id)
        .expect("Bob discovered by Alice");
    let bob_photo_hash = bob_candidate.profile.photos[0].hash;
    let fetched_bob = alice
        .fetch_photo(bob_id, bob_photo_hash)
        .await
        .expect("Alice validates Bob's photo");
    assert_eq!(ContentHash::digest(&fetched_bob.bytes), bob_photo_hash);

    let cancelled = annoda_network::SyncCancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        bob.like_with_cancellation(alice_id, cancelled).await,
        Err(annoda_network::client::ClientError::Cancelled)
    ));
    bob.close();
    let mut bob = AnnodaClient::open(client_config("bob"), b"bob application passphrase")
        .expect("restart Bob with durable like");
    let sync_started = tokio::time::Instant::now();
    let recovered = bob
        .sync(Default::default())
        .await
        .expect("public sync retries the exact persisted parcel");
    assert_eq!(recovered.status, annoda_network::SyncStatus::Complete);
    assert!(sync_started.elapsed() <= Duration::from_secs(15));
    assert!(recovered.downloaded_bytes <= SyncBudget::default().max_download_bytes);
    assert!(recovered.uploaded_bytes <= SyncBudget::default().max_upload_bytes);
    let incoming = alice
        .sync(Default::default())
        .await
        .expect("Alice receives like");
    assert!(!incoming.new_events.is_empty());
    let likes = alice
        .received_likes(20, None)
        .await
        .expect("incoming likes");
    assert!(likes.items.iter().any(|like| {
        like.sender == bob_id
            && like.state == MatchState::Incoming
            && like.credential.claims.first_name == "Bob"
    }));
    alice
        .sync(Default::default())
        .await
        .expect("repeat sync is idempotent");
    assert_eq!(
        alice
            .received_likes(20, None)
            .await
            .expect("single incoming intent")
            .items
            .len(),
        1
    );
    assert!(
        alice
            .matches(20, None)
            .await
            .expect("no match before reciprocation")
            .items
            .is_empty()
    );
    let bob_candidates = alice
        .discover(Default::default())
        .await
        .expect("discover Bob for reciprocation");
    assert!(
        bob_candidates
            .items
            .iter()
            .any(|candidate| candidate.profile.owner == bob_id)
    );
    alice.like(bob_id).await.expect("Alice reciprocates");
    bob.sync(Default::default())
        .await
        .expect("Bob receives reciprocal like");
    let matched = bob.matches(20, None).await.expect("Bob match page");
    let match_record = matched
        .items
        .iter()
        .find(|item| item.peer == alice_id)
        .expect("mutual match");
    let alice_match = alice
        .matches(20, None)
        .await
        .expect("Alice match page")
        .items
        .into_iter()
        .find(|item| item.peer == bob_id)
        .expect("same match visible to Alice");
    assert_eq!(alice_match.match_id, match_record.match_id);
    assert!(
        !postcard::to_allocvec(&alice_candidate.profile)
            .expect("serialize signed profile")
            .windows(b"@bob-public-test".len())
            .any(|window| window == b"@bob-public-test")
    );

    bob.disclose_match_contacts(
        match_record.match_id,
        vec![ContactHandle {
            service: ContactService::Telegram,
            value: "@bob-public-test".into(),
        }],
    )
    .await
    .expect("consensual contact disclosure");
    alice
        .disclose_match_contacts(
            match_record.match_id,
            vec![ContactHandle {
                service: ContactService::WhatsApp,
                value: "+390000000000".into(),
            }],
        )
        .await
        .expect("Alice explicitly shares a separate contact");
    bob.sync(Default::default())
        .await
        .expect("Bob receives Alice's contact");
    alice
        .sync(Default::default())
        .await
        .expect("Alice receives contact parcel");
    assert_eq!(
        alice
            .received_match_contacts(match_record.match_id)
            .await
            .expect("contacts"),
        vec![ContactHandle {
            service: ContactService::Telegram,
            value: "@bob-public-test".into()
        }]
    );
    assert_eq!(
        bob.received_match_contacts(match_record.match_id)
            .await
            .expect("Bob receives Alice's contacts"),
        vec![ContactHandle {
            service: ContactService::WhatsApp,
            value: "+390000000000".into()
        }]
    );

    let match_id = match_record.match_id;
    alice.close();
    let mut alice = AnnodaClient::open(client_config("alice"), b"alice application passphrase")
        .expect("restart Alice client");
    assert_eq!(
        alice.identity_summary().expect("same identity").profile_id,
        alice_id
    );
    assert_eq!(
        alice
            .published_profile()
            .expect("own profile survives restart")
            .expect("profile is still published")
            .revision,
        alice_publication.revision
    );
    assert!(
        alice
            .matches(20, None)
            .await
            .expect("persisted match")
            .items
            .iter()
            .any(|item| item.match_id == match_id)
    );
    assert_eq!(
        alice
            .received_match_contacts(match_id)
            .await
            .expect("contacts survive restart"),
        vec![ContactHandle {
            service: ContactService::Telegram,
            value: "@bob-public-test".into()
        }]
    );
    assert!(
        alice
            .received_likes(20, None)
            .await
            .expect("likes survive restart")
            .items
            .iter()
            .any(|like| like.sender == bob_id)
    );
    alice.block(bob_id).await.expect("block match");
    assert!(matches!(
        alice.like(bob_id).await,
        Err(annoda_network::client::ClientError::Unauthorized)
    ));
    assert!(matches!(
        alice.received_match_contacts(match_id).await,
        Err(annoda_network::client::ClientError::Unauthorized)
    ));
    assert!(matches!(
        alice
            .disclose_match_contacts(
                match_id,
                vec![ContactHandle {
                    service: ContactService::Telegram,
                    value: "@blocked-share-attempt".into(),
                }],
            )
            .await,
        Err(annoda_network::client::ClientError::Unauthorized)
    ));
    assert!(
        !alice
            .discover(Default::default())
            .await
            .expect("blocked profile excluded")
            .items
            .iter()
            .any(|candidate| candidate.profile.owner == bob_id)
    );

    bob.close();
    alice.close();
    volunteer_a.shutdown().await;
    volunteer_b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_receipt_reports_partial_replica_and_unreachable_peer() {
    let issuer = DevelopmentIssuer::new().expect("development issuer");
    let issuers = issuer.trusted_issuers();
    let clock = Arc::new(ManualClock::new(NOW));
    let root = TempDir::new().expect("test root");
    let live = PeerNode::start(
        NodeConfig {
            data_dir: root.path().join("live-volunteer"),
            clock: clock.clone(),
            request_timeout: Duration::from_secs(1),
            ..NodeConfig::default()
        },
        issuers.clone(),
    )
    .await
    .expect("live volunteer");
    let live_address = live.wait_for_listeners().await.expect("live listener")[0].clone();
    let unreachable = PeerNode::start(
        NodeConfig {
            data_dir: root.path().join("stopped-volunteer"),
            clock: clock.clone(),
            request_timeout: Duration::from_secs(1),
            ..NodeConfig::default()
        },
        issuers.clone(),
    )
    .await
    .expect("second volunteer identity");
    let stopped_peer = unreachable.peer_id().to_string();
    let stopped_address = unreachable
        .wait_for_listeners()
        .await
        .expect("second listener")[0]
        .clone();
    unreachable.shutdown().await;
    let peers = vec![
        SyncPeerAddress {
            peer_id: live.peer_id().to_string(),
            address: live_address.to_string(),
        },
        SyncPeerAddress {
            peer_id: stopped_peer,
            address: stopped_address.to_string(),
        },
    ];
    let mut client = AnnodaClient::create(
        ClientConfig::new(root.path().join("client"), peers.clone(), issuers.clone())
            .with_clock(clock.clone())
            .with_sync_budget(SyncBudget {
                max_duration: Duration::from_secs(6),
                max_mailbox_items: 8,
                ..SyncBudget::default()
            })
            .with_safety_classifier(
                Arc::new(DeterministicSafetyFixture::new(0.0).expect("fixture")),
                true,
            ),
        b"partial-replica passphrase",
    )
    .expect("application account");
    let identity = client.identity_summary().expect("public identity");
    client
        .attach_credential(
            issuer
                .issue(IssuanceRequest {
                    signing_key: identity.signing_public_key,
                    encryption_key: identity.encryption_public_key,
                    first_name: "Partial".into(),
                    age_at_issue: 29,
                    issued_at: NOW - 1,
                    expires_at: NOW + 10_000,
                })
                .expect("synthetic issuer credential"),
        )
        .expect("attach credential");

    let receipt = client
        .publish_profile(vec![jpeg(42)])
        .await
        .expect("durable publication returns a receipt");
    assert_eq!(receipt.replicated_peers, 1);
    assert_eq!(
        receipt.operation.status,
        annoda_core::storage::OutgoingOperationStatus::Partial
    );
    assert!(receipt.operation.failures.iter().any(|failure| {
        failure.reason == annoda_network::client::DeliveryFailureReason::Unreachable
    }));
    assert!(receipt.operation.retry_recommended);

    client.close();
    let account_dir = root.path().join("client");
    let zero_budget_config = || {
        ClientConfig::new(&account_dir, peers.clone(), issuers.clone())
            .with_clock(clock.clone())
            .with_sync_budget(SyncBudget {
                max_duration: Duration::from_secs(2),
                max_mailbox_items: 0,
                max_download_bytes: 0,
                max_upload_bytes: 0,
                ..SyncBudget::default()
            })
    };
    let mut zero_budget = AnnodaClient::open(zero_budget_config(), b"partial-replica passphrase")
        .expect("reopen account with zero transfer budget");
    let report = zero_budget
        .sync(Default::default())
        .await
        .expect("zero-byte M3 sync is exhausted without network activity");
    assert_eq!(report.status, annoda_network::SyncStatus::BudgetExhausted);
    assert_eq!(report.downloaded_bytes, 0);
    assert_eq!(report.uploaded_bytes, 0);
    zero_budget.close();

    let tiny_budget_config = || {
        ClientConfig::new(&account_dir, peers.clone(), issuers.clone())
            .with_clock(clock.clone())
            .with_sync_budget(SyncBudget {
                max_duration: Duration::from_secs(2),
                max_mailbox_items: 8,
                max_download_bytes: 1,
                max_upload_bytes: 1,
                request_timeout: Duration::from_secs(1),
                ..SyncBudget::default()
            })
    };
    let mut tiny_budget = AnnodaClient::open(tiny_budget_config(), b"partial-replica passphrase")
        .expect("reopen account with one-byte transfer caps");
    let started = tokio::time::Instant::now();
    let report = tiny_budget
        .sync(Default::default())
        .await
        .expect("bounded M3 sync returns a report");
    assert!(started.elapsed() <= Duration::from_secs(3));
    assert!(report.downloaded_bytes <= 1);
    assert!(report.uploaded_bytes <= 1);
    tiny_budget.close();
    live.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_photo_fetch_skips_corrupt_replicas_and_fails_closed_when_all_are_corrupt() {
    let issuer = DevelopmentIssuer::new().expect("development issuer");
    let issuers = issuer.trusted_issuers();
    let clock = Arc::new(ManualClock::new(NOW));
    let root = TempDir::new().expect("test root");
    let volunteer_a_dir = root.path().join("volunteer-a");
    let volunteer_b_dir = root.path().join("volunteer-b");
    let volunteer_a = PeerNode::start(
        NodeConfig {
            data_dir: volunteer_a_dir.clone(),
            clock: clock.clone(),
            request_timeout: Duration::from_secs(2),
            ..NodeConfig::default()
        },
        issuers.clone(),
    )
    .await
    .expect("volunteer A");
    let address_a = volunteer_a.wait_for_listeners().await.expect("A listener")[0].clone();
    let volunteer_b = PeerNode::start(
        NodeConfig {
            data_dir: volunteer_b_dir.clone(),
            clock: clock.clone(),
            request_timeout: Duration::from_secs(2),
            ..NodeConfig::default()
        },
        issuers.clone(),
    )
    .await
    .expect("volunteer B");
    let address_b = volunteer_b.wait_for_listeners().await.expect("B listener")[0].clone();
    let peers = vec![
        SyncPeerAddress {
            peer_id: volunteer_a.peer_id().to_string(),
            address: address_a.to_string(),
        },
        SyncPeerAddress {
            peer_id: volunteer_b.peer_id().to_string(),
            address: address_b.to_string(),
        },
    ];
    let safety = || {
        Arc::new(DeterministicSafetyFixture::new(0.0).expect("fixture"))
            as Arc<dyn annoda_intelligence::safety::PhotoSafetyClassifier>
    };
    let config = |name: &str| {
        ClientConfig::new(root.path().join(name), peers.clone(), issuers.clone())
            .with_clock(clock.clone())
            .with_sync_budget(SyncBudget {
                max_duration: Duration::from_secs(15),
                max_mailbox_items: 16,
                ..SyncBudget::default()
            })
            .with_safety_classifier(safety(), true)
    };
    let mut alice = AnnodaClient::create(config("alice"), b"Alice photo test passphrase")
        .expect("Alice account");
    let mut bob =
        AnnodaClient::create(config("bob"), b"Bob photo test passphrase").expect("Bob account");
    let alice_identity = alice.identity_summary().expect("Alice identity");
    let bob_identity = bob.identity_summary().expect("Bob identity");
    alice
        .attach_credential(
            issuer
                .issue(IssuanceRequest {
                    signing_key: alice_identity.signing_public_key,
                    encryption_key: alice_identity.encryption_public_key,
                    first_name: "Alice".into(),
                    age_at_issue: 28,
                    issued_at: NOW - 1,
                    expires_at: NOW + 10_000,
                })
                .expect("Alice credential"),
        )
        .expect("attach Alice credential");
    bob.attach_credential(
        issuer
            .issue(IssuanceRequest {
                signing_key: bob_identity.signing_public_key,
                encryption_key: bob_identity.encryption_public_key,
                first_name: "Bob".into(),
                age_at_issue: 30,
                issued_at: NOW - 1,
                expires_at: NOW + 10_000,
            })
            .expect("Bob credential"),
    )
    .expect("attach Bob credential");

    alice
        .publish_profile(vec![jpeg(31)])
        .await
        .expect("replicate Alice's photo");
    let profile = alice
        .published_profile()
        .expect("own profile")
        .expect("published profile");
    let hash = profile.photos[0].hash;
    bob.discover(Default::default())
        .await
        .expect("discover Alice's profile");

    corrupt_volunteer_blob(&volunteer_a_dir, hash);
    let fallback = bob
        .fetch_photo(profile.owner, hash)
        .await
        .expect("fetch falls back to the valid second replica");
    assert_eq!(ContentHash::digest(&fallback.bytes), hash);

    corrupt_volunteer_blob(&volunteer_b_dir, hash);
    assert!(matches!(
        bob.fetch_photo(profile.owner, hash).await,
        Err(annoda_network::client::ClientError::NetworkUnavailable)
    ));

    bob.close();
    alice.close();
    volunteer_a.shutdown().await;
    volunteer_b.shutdown().await;
}

fn corrupt_volunteer_blob(data_dir: &std::path::Path, hash: ContentHash) {
    let connection = Connection::open(data_dir.join("peer-storage.sqlite3"))
        .expect("open volunteer fixture database");
    let mut bytes: Vec<u8> = connection
        .query_row(
            "SELECT data FROM blobs WHERE hash=?1",
            [hash.0.as_slice()],
            |row| row.get(0),
        )
        .expect("replicated blob");
    assert!(!bytes.is_empty());
    bytes[0] ^= 0xFF;
    connection
        .execute(
            "UPDATE blobs SET data=?1 WHERE hash=?2",
            rusqlite::params![bytes, hash.0.as_slice()],
        )
        .expect("corrupt test fixture replica");
}
