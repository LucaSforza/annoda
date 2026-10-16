use std::{
    collections::HashSet,
    io::Cursor,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use annoda_core::{
    identity::{DevelopmentIssuer, IdentityIssuer, IssuanceRequest},
    protocol::ProfileId,
};
use annoda_intelligence::{
    ranking::{
        CandidateFilter, EncoderMode, PhotoEmbedding, PhotoEncoder, RankingCandidate, RankingError,
    },
    safety::DeterministicSafetyFixture,
};
use annoda_network::{
    ManualClock, NodeConfig, PeerNode, SyncBudget, SyncPeerAddress,
    client::{AnnodaClient, ClientConfig, ClientError, PageCursor},
};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use tempfile::TempDir;

const NOW: u64 = 2_000;

fn jpeg() -> Vec<u8> {
    let pixels = ImageBuffer::from_fn(32, 24, |x, y| Rgb([x as u8, y as u8, 90]));
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(pixels)
        .write_to(&mut output, ImageFormat::Jpeg)
        .expect("encode JPEG");
    output.into_inner()
}

fn config(directory: &std::path::Path, issuer: &DevelopmentIssuer) -> ClientConfig {
    ClientConfig::new(directory, vec![], issuer.trusted_issuers())
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_sync_budget(annoda_network::SyncBudget {
            max_duration: Duration::from_secs(2),
            ..Default::default()
        })
}

fn offline_peer() -> Vec<SyncPeerAddress> {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = libp2p::PeerId::from_public_key(&key.public());
    vec![SyncPeerAddress {
        peer_id: peer.to_string(),
        address: "/ip4/127.0.0.1/tcp/1".into(),
    }]
}

struct RenamedFixtureEncoder(Arc<AtomicUsize>);

impl PhotoEncoder for RenamedFixtureEncoder {
    fn encode(&self, _photo: &[u8]) -> Result<PhotoEmbedding, RankingError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        PhotoEmbedding::new(1, vec![0.5])
    }

    fn description(&self) -> &'static str {
        "renamed byte fixture"
    }

    fn mode(&self) -> EncoderMode {
        EncoderMode::DevelopmentFixture
    }
}

fn issue_for(
    client: &AnnodaClient,
    issuer: &DevelopmentIssuer,
    name: &str,
    expires_at: u64,
) -> annoda_core::identity::VerifiedCredential {
    let identity = client.identity_summary().expect("identity");
    issuer
        .issue(IssuanceRequest {
            signing_key: identity.signing_public_key,
            encryption_key: identity.encryption_public_key,
            first_name: name.into(),
            age_at_issue: 28,
            issued_at: NOW - 1,
            expires_at,
        })
        .expect("issuer credential")
}

#[tokio::test]
async fn credentials_are_bound_to_both_keys_and_reports_restore_from_local_storage() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let root = TempDir::new().expect("directory");
    let mut alice = AnnodaClient::create(
        config(&root.path().join("alice"), &issuer),
        b"alice password",
    )
    .expect("Alice");
    let bob = AnnodaClient::create(config(&root.path().join("bob"), &issuer), b"bob password")
        .expect("Bob");
    let bob_credential = issue_for(&bob, &issuer, "Bob", NOW + 100);
    assert!(matches!(
        alice.attach_credential(bob_credential),
        Err(ClientError::UntrustedIdentity)
    ));
    let alice_identity = alice.identity_summary().expect("Alice identity");
    let bob_identity = bob.identity_summary().expect("Bob identity");
    let mixed_keys = issuer
        .issue(IssuanceRequest {
            signing_key: alice_identity.signing_public_key,
            encryption_key: bob_identity.encryption_public_key,
            first_name: "Alice".into(),
            age_at_issue: 28,
            issued_at: NOW - 1,
            expires_at: NOW + 100,
        })
        .expect("credential with mismatched account encryption key");
    assert!(matches!(
        alice.attach_credential(mixed_keys),
        Err(ClientError::UntrustedIdentity)
    ));
    let other_issuer = DevelopmentIssuer::new().expect("other issuer");
    let untrusted = issue_for(&alice, &other_issuer, "Alice", NOW + 100);
    assert!(matches!(
        alice.attach_credential(untrusted),
        Err(ClientError::UntrustedIdentity)
    ));

    let alice_credential = issue_for(&alice, &issuer, "Alice", NOW + 100);
    alice
        .attach_credential(alice_credential)
        .expect("Alice credential");
    let subject = bob.identity_summary().expect("Bob identity").profile_id;
    let report = alice
        .report_profile(subject, 1, vec![[7; 32]])
        .expect("local signed report");
    assert!(report.validate_bounds().is_ok());
    for index in 0..64u8 {
        alice
            .report_profile(subject, 1, vec![[index; 32]])
            .expect("additional bounded report");
    }
    let first_page = alice
        .local_reports_page(64, None)
        .expect("first report page");
    assert_eq!(first_page.items.len(), 64);
    let cursor = first_page.next_cursor.expect("next report cursor");
    let second_page = alice
        .local_reports_page(64, Some(cursor))
        .expect("second report page");
    assert_eq!(second_page.items.len(), 1);
    assert!(second_page.next_cursor.is_none());
    let alice_id = alice.identity_summary().expect("Alice identity").profile_id;
    alice.close();

    let reopened = AnnodaClient::open(
        config(&root.path().join("alice"), &issuer),
        b"alice password",
    )
    .expect("reopen Alice");
    let reports = reopened
        .local_reports_page(64, None)
        .expect("signed report history");
    assert_eq!(reports.items.len(), 64);
    assert!(reports.items.contains(&report));
    assert_eq!(
        reopened
            .identity_summary()
            .expect("same identity")
            .profile_id,
        alice_id
    );
}

#[tokio::test]
async fn publication_fails_closed_without_real_safety_or_explicit_fixture_opt_in() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let root = TempDir::new().expect("directory");
    let mut unavailable = AnnodaClient::create(
        ClientConfig::new(
            root.path().join("unavailable"),
            offline_peer(),
            issuer.trusted_issuers(),
        )
        .with_clock(Arc::new(ManualClock::new(NOW))),
        b"passphrase",
    )
    .expect("account");
    let credential = issue_for(&unavailable, &issuer, "Alice", NOW + 100);
    unavailable
        .attach_credential(credential)
        .expect("credential");
    assert!(matches!(
        unavailable.publish_profile(vec![jpeg()]).await,
        Err(ClientError::SafetyUnavailable)
    ));

    let fixture = Arc::new(DeterministicSafetyFixture::new(0.0).expect("fixture"));
    let mut rejected_fixture = AnnodaClient::create(
        ClientConfig::new(
            root.path().join("fixture"),
            offline_peer(),
            issuer.trusted_issuers(),
        )
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_safety_classifier(fixture, false),
        b"passphrase",
    )
    .expect("fixture account");
    let credential = issue_for(&rejected_fixture, &issuer, "Alice", NOW + 100);
    rejected_fixture
        .attach_credential(credential)
        .expect("credential");
    assert!(matches!(
        rejected_fixture.publish_profile(vec![jpeg()]).await,
        Err(ClientError::SafetyUnavailable)
    ));

    let fixture = Arc::new(DeterministicSafetyFixture::new(0.0).expect("fixture"));
    let mut bad_photo = AnnodaClient::create(
        ClientConfig::new(
            root.path().join("bad-photo"),
            offline_peer(),
            issuer.trusted_issuers(),
        )
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_safety_classifier(fixture, true),
        b"passphrase",
    )
    .expect("photo account");
    assert!(
        bad_photo
            .publish_profile(vec![b"not an image".to_vec()])
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_photo_fetch_does_not_run_renamed_development_encoder_without_opt_in() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let root = TempDir::new().expect("directory");
    let peer = PeerNode::start(
        NodeConfig {
            data_dir: root.path().join("peer"),
            clock: Arc::new(ManualClock::new(NOW)),
            request_timeout: Duration::from_secs(2),
            ..NodeConfig::default()
        },
        issuer.trusted_issuers(),
    )
    .await
    .expect("volunteer peer");
    let address = peer.wait_for_listeners().await.expect("listener")[0].clone();
    let peers = vec![SyncPeerAddress {
        peer_id: peer.peer_id().to_string(),
        address: address.to_string(),
    }];
    let clock = Arc::new(ManualClock::new(NOW));
    let safety = || Arc::new(DeterministicSafetyFixture::new(0.0).expect("safety fixture"));
    let budget = SyncBudget {
        max_duration: Duration::from_secs(10),
        max_mailbox_items: 16,
        ..SyncBudget::default()
    };
    let mut publisher = AnnodaClient::create(
        ClientConfig::new(
            root.path().join("publisher"),
            peers.clone(),
            issuer.trusted_issuers(),
        )
        .with_clock(clock.clone())
        .with_sync_budget(budget.clone())
        .with_safety_classifier(safety(), true),
        b"publisher passphrase",
    )
    .expect("publisher account");
    publisher
        .attach_credential(issue_for(&publisher, &issuer, "Bob", NOW + 100))
        .expect("publisher credential");
    publisher
        .publish_profile(vec![jpeg()])
        .await
        .expect("publish validated photo");
    let profile = publisher
        .published_profile()
        .expect("local profile")
        .expect("published profile");
    let hash = profile.photos[0].hash;

    let calls = Arc::new(AtomicUsize::new(0));
    let mut downloader = AnnodaClient::create(
        ClientConfig::new(
            root.path().join("downloader"),
            peers,
            issuer.trusted_issuers(),
        )
        .with_clock(clock)
        .with_sync_budget(budget)
        .with_safety_classifier(safety(), true)
        .with_photo_encoder(Arc::new(RenamedFixtureEncoder(Arc::clone(&calls))), false),
        b"downloader passphrase",
    )
    .expect("downloader account");
    let photo = downloader
        .fetch_photo(profile.owner, hash)
        .await
        .expect("public fetch returns the validated photo");
    assert_eq!(photo.hash, hash);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    peer.shutdown().await;
}

#[tokio::test]
async fn match_contacts_require_a_persisted_mutual_match() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let root = TempDir::new().expect("directory");
    let mut alice =
        AnnodaClient::create(config(&root.path().join("alice"), &issuer), b"passphrase")
            .expect("account");
    let credential = issue_for(&alice, &issuer, "Alice", NOW + 100);
    alice.attach_credential(credential).expect("credential");
    assert!(matches!(
        alice.disclose_match_contacts([3; 32], vec![]).await,
        Err(ClientError::Unauthorized)
    ));
    assert!(matches!(
        alice.received_match_contacts([3; 32]).await,
        Err(ClientError::Unauthorized)
    ));
    assert!(matches!(
        alice.matches(20, Some(PageCursor(vec![0]))).await,
        Err(ClientError::InvalidInput)
    ));
    let peer = ProfileId([9; 32]);
    alice.block(peer).await.expect("block without prior match");
    assert!(matches!(
        alice.pass(peer).await,
        Err(ClientError::Unauthorized)
    ));
}

#[test]
fn expired_credential_is_rejected_at_attach_time() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let root = TempDir::new().expect("directory");
    let clock = Arc::new(ManualClock::new(NOW));
    let mut client = AnnodaClient::create(
        ClientConfig::new(root.path().join("alice"), vec![], issuer.trusted_issuers())
            .with_clock(clock.clone()),
        b"passphrase",
    )
    .expect("account");
    let credential = issue_for(&client, &issuer, "Alice", NOW + 1);
    clock.set(NOW + 2);
    assert!(matches!(
        client.attach_credential(credential),
        Err(ClientError::CredentialExpired)
    ));
}

#[test]
fn invalid_feedback_does_not_mutate_pass_state_and_model_restores() {
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let root = TempDir::new().expect("directory");
    let path = root.path().join("alice");
    let mut client = AnnodaClient::create(config(&path, &issuer), b"passphrase").expect("account");
    let peer = ProfileId([9; 32]);
    let peer_id = peer
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let invalid = PhotoEmbedding {
        version: 1,
        values: vec![f64::NAN],
    };
    assert!(matches!(
        client.record_feedback(peer, &invalid, false),
        Err(ClientError::InvalidInput)
    ));
    let candidate = |id: String| RankingCandidate {
        id,
        verified_age: 28,
        adult_credential_valid: true,
        coarse_region: None,
        embedding: PhotoEmbedding::new(1, vec![0.8]).expect("valid embedding"),
    };
    let filter = CandidateFilter {
        minimum_age: 18,
        maximum_age: 90,
        coarse_region: None,
        blocked: HashSet::new(),
        passed: HashSet::new(),
        seen: HashSet::new(),
    };
    let unchanged = client
        .rank_candidates(&[candidate(peer_id.clone())], &filter, 0.0, 1)
        .expect("rank after invalid feedback");
    assert_eq!(unchanged.len(), 1);
    assert_eq!(unchanged[0].score.probability, 0.5);

    client
        .record_feedback(
            peer,
            &PhotoEmbedding::new(1, vec![0.8]).expect("valid embedding"),
            false,
        )
        .expect("record valid pass feedback");
    client.close();
    let restored =
        AnnodaClient::open(config(&path, &issuer), b"passphrase").expect("reopen account");
    let ranked = restored
        .rank_candidates(&[candidate("other-profile".into())], &filter, 0.0, 1)
        .expect("rank after model restoration");
    assert!(ranked[0].score.probability < 0.5);
}
