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
