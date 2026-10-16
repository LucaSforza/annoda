use super::*;

#[test]
fn exported_ranker_is_local_and_reports_typed_input_errors() {
    let ranker = LocalPreferenceModel::new(2, 7);
    assert!(ranker.is_ok());
    let Ok(ranker) = ranker else {
        return;
    };
    assert_eq!(
        ranker
            .score(7, vec![0.3, 0.4])
            .map(|score| score.probability),
        Ok(0.5)
    );
    assert_eq!(ranker.score(7, vec![0.3]), Err(FfiError::IncompatibleModel));
    assert_eq!(ranker.record_feedback(7, vec![0.3, 0.4], true), Ok(()));
    assert!(
        ranker
            .score(7, vec![0.3, 0.4])
            .is_ok_and(|score| score.probability > 0.5)
    );
    assert_eq!(ranker.reset(), Ok(()));
    assert_eq!(
        ranker
            .score(7, vec![0.3, 0.4])
            .map(|score| score.probability),
        Ok(0.5)
    );
}

#[test]
fn constructor_bounds_model_allocation() {
    assert_eq!(
        LocalPreferenceModel::new(0, 1).err(),
        Some(FfiError::InvalidInput)
    );
    assert_eq!(
        LocalPreferenceModel::new(MAX_MODEL_DIMENSIONS + 1, 1).err(),
        Some(FfiError::InvalidInput)
    );
}

#[test]
fn portable_account_ffi_reopens_stable_identity_and_maps_wrong_passphrase() {
    let temporary = tempfile::tempdir().expect("account directory");
    let directory = temporary
        .path()
        .join("account")
        .to_string_lossy()
        .into_owned();
    let account = create_account(directory.clone(), "correct horse battery".to_owned())
        .expect("create account");
    let profile_id = account.profile_id().expect("profile id");
    account
        .set_notification_preferences(FfiNotificationPreferences {
            likes_enabled: false,
            matches_enabled: true,
        })
        .expect("save prefs");
    account.lock().expect("lock account");
    assert_eq!(account.profile_id(), Err(FfiError::AccountLocked));
    assert_eq!(
        open_account(directory.clone(), "wrong passphrase".to_owned()).err(),
        Some(FfiError::AuthenticationFailed)
    );

    let restored =
        open_account(directory, "correct horse battery".to_owned()).expect("reopen account");
    assert_eq!(restored.profile_id().expect("restored id"), profile_id);
    assert_eq!(
        restored.notification_preferences().expect("restored prefs"),
        FfiNotificationPreferences {
            likes_enabled: false,
            matches_enabled: true,
        }
    );
}

#[test]
fn no_peer_sync_uses_valid_account_context_and_returns_a_deferred_report() {
    use annoda_core::{AccountKeyStore, PortableAccountVault, identity::DevelopmentIssuer};
    use std::time::SystemTime;

    let temporary = tempfile::tempdir().expect("account directory");
    let directory = temporary.path().join("account");
    let secret = b"session test passphrase";
    let unlocked = PortableAccountVault::new(&directory)
        .create(secret)
        .expect("create account");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let credential = issuer
        .issue_synthetic(
            unlocked.identity(),
            "Synthetic Fixture",
            24,
            now.saturating_sub(1),
            now.saturating_add(3600),
        )
        .expect("credential");
    let account = Arc::new(AccountHandle::new(directory.clone(), unlocked));
    let request = FfiSyncRequest {
        credential: postcard::to_allocvec(&credential).expect("credential bytes"),
        trusted_issuer_keys: vec![issuer.public_key().to_vec()],
        revoked_serials: Vec::new(),
        peers: Vec::new(),
        budget: FfiSyncBudget {
            max_duration_ms: 10_000,
            max_download_bytes: 1024,
            max_upload_bytes: 1024,
            max_peers: 1,
            max_mailbox_items: 4,
            max_concurrent_requests: 1,
            retries: 0,
            request_timeout_ms: 1000,
        },
        contribution_policy: FfiPeerContributionPolicy {
            enabled: false,
            wifi_only: true,
            charging_only: false,
            max_storage_bytes: 0,
            max_transfer_bytes: 0,
            max_duration_ms: 0,
        },
        host_conditions: FfiHostConditions {
            wifi_available: Some(false),
            charging: Some(false),
        },
        authorized_replicas: Vec::new(),
    };
    let mut mismatched_request = request.clone();
    let other_device = annoda_core::DeviceKeyPair::generate().expect("other device");
    let mismatched_credential = issuer
        .issue_synthetic(
            &other_device,
            "Synthetic Peer",
            26,
            now.saturating_sub(1),
            now.saturating_add(3600),
        )
        .expect("mismatched credential");
    mismatched_request.credential =
        postcard::to_allocvec(&mismatched_credential).expect("credential bytes");
    let session = account
        .start_sync_session(request)
        .expect("start valid no-peer sync");
    session.cancel();
    assert_eq!(session.wait_result(u64::MAX), Err(FfiError::InvalidInput));
    let report = session
        .wait_result(5000)
        .expect("wait for report")
        .expect("completed session");
    assert_eq!(report.status, FfiSyncStatus::Deferred);
    assert_eq!(
        report.deferred_reasons,
        vec![FfiSyncDeferredReason::NoPeers]
    );
    assert!(report.contacted_peers.is_empty());
    let failed = account
        .start_sync_session(mismatched_request)
        .expect("start rejected identity sync");
    assert_eq!(failed.wait_result(5000), Err(FfiError::Unauthorized));
    account.lock().expect("lock after session");
    assert!(PortableAccountVault::new(directory).unlock(secret).is_ok());
}

#[test]
fn sync_context_reconstructs_only_bounded_signed_replica_inputs() {
    use annoda_core::{
        DeviceKeyPair,
        identity::DevelopmentIssuer,
        protocol::{ContentLease, PhotoManifest, PublicProfile},
    };
    use std::time::SystemTime;

    let owner = DeviceKeyPair::generate().expect("owner");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let credential = issuer
        .issue_synthetic(
            &owner,
            "Synthetic Fixture",
            24,
            now.saturating_sub(1),
            now.saturating_add(3600),
        )
        .expect("credential");
    let trust = issuer.trusted_issuers();
    let bytes = b"bounded test image";
    let manifest = PhotoManifest::from_bytes(bytes, "image/jpeg").expect("manifest");
    let lease = ContentLease::issue(
        &owner,
        &credential,
        &manifest,
        now,
        now.saturating_add(1800),
        &trust,
    )
    .expect("lease");
    let profile = PublicProfile::create(
        &owner,
        credential.clone(),
        vec![manifest.clone()],
        now.saturating_add(1800),
        &trust,
        now,
    )
    .expect("profile");
    let request = FfiSyncRequest {
        credential: postcard::to_allocvec(&credential).expect("credential bytes"),
        trusted_issuer_keys: vec![issuer.public_key().to_vec()],
        revoked_serials: Vec::new(),
        peers: Vec::new(),
        budget: FfiSyncBudget {
            max_duration_ms: 1000,
            max_download_bytes: 1024,
            max_upload_bytes: 1024,
            max_peers: 1,
            max_mailbox_items: 4,
            max_concurrent_requests: 1,
            retries: 0,
            request_timeout_ms: 500,
        },
        contribution_policy: FfiPeerContributionPolicy {
            enabled: true,
            wifi_only: true,
            charging_only: false,
            max_storage_bytes: 1024 * 1024,
            max_transfer_bytes: 1024,
            max_duration_ms: 1000,
        },
        host_conditions: FfiHostConditions {
            wifi_available: Some(true),
            charging: Some(false),
        },
        authorized_replicas: vec![FfiAuthorizedReplica {
            profile: postcard::to_allocvec(&profile).expect("profile bytes"),
            owner_credential: postcard::to_allocvec(&credential).expect("owner credential bytes"),
            photos: vec![FfiAuthorizedReplicaPhoto {
                manifest: postcard::to_allocvec(&manifest).expect("manifest bytes"),
                lease: postcard::to_allocvec(&lease).expect("lease bytes"),
                bytes: bytes.to_vec(),
            }],
        }],
    };
    let context = build_sync_context(std::path::Path::new("/tmp/ffi-test"), &request)
        .expect("authorized replica context");
    assert!(context.contribution.policy.enabled);
    assert_eq!(context.contribution.replicas.len(), 1);
    assert_eq!(context.contribution.replicas[0].photos.len(), 1);
    assert_eq!(context.contribution.replicas[0].photos[0].bytes, bytes);
}
