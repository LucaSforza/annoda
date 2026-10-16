use std::{sync::Arc, time::Duration};

use annoda_core::{
    AccountKeyStore, PortableAccountVault,
    identity::DevelopmentIssuer,
    matching::{ContactHandle, ContactService},
    protocol::MailboxParcel,
    storage::{PeerStorage, StorageLimits},
};
use annoda_network::{
    ManualClock, NodeConfig, PeerNode, SyncBudget, SyncContext, SyncPeerAddress, SyncStatus,
    sync_once,
};
use tempfile::TempDir;

const NOW: u64 = 2_000;

fn config(dir: &TempDir, clock: Arc<ManualClock>) -> NodeConfig {
    NodeConfig {
        data_dir: dir.path().to_owned(),
        request_timeout: Duration::from_secs(2),
        bandwidth_bytes_per_second: 64 * 1024 * 1024,
        clock,
        ..NodeConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restored_offline_account_syncs_a_like_once_and_acknowledged_events_stay_acknowledged() {
    let issuer = DevelopmentIssuer::new().unwrap();
    let issuers = issuer.trusted_issuers();
    let account_dir = TempDir::new().unwrap();
    let vault = PortableAccountVault::new(account_dir.path().join("vault"));
    let alice_first = vault.create(b"sync-test-passphrase").unwrap();
    let alice_credential = issuer
        .issue_synthetic(alice_first.identity(), "Alice", 28, NOW - 1, NOW + 8_000)
        .unwrap();
    let alice_id = alice_credential.profile_id();
    alice_first.lock();

    let bob_account_dir = TempDir::new().unwrap();
    let bob_vault = PortableAccountVault::new(bob_account_dir.path().join("vault"));
    let bob_account = bob_vault.create(b"bob-sync-passphrase").unwrap();
    let bob_credential = issuer
        .issue_synthetic(bob_account.identity(), "Bob", 30, NOW - 1, NOW + 8_000)
        .unwrap();
    let bob_id = bob_credential.profile_id();
    let bob_state_path = bob_account_dir.path().join("sync-state.sqlite3");
    let mut bob_state = PeerStorage::open(&bob_state_path, StorageLimits::default()).unwrap();
    bob_state
        .apply_local_like(bob_id, alice_id, [91; 16])
        .unwrap();
    let mut bob_match = bob_state.load_match(bob_id, alice_id).unwrap().unwrap();
    let envelope = bob_match
        .create_like_envelope(
            bob_account.identity(),
            &bob_credential,
            &alice_credential,
            [91; 16],
            NOW,
            NOW + 1_000,
            &issuers,
        )
        .unwrap();
    let parcel =
        MailboxParcel::create(&envelope, &bob_credential, &alice_credential, &issuers, NOW)
            .unwrap();

    let carol_device = annoda_core::identity::DeviceKeyPair::generate().unwrap();
    let carol_credential = issuer
        .issue_synthetic(&carol_device, "Carol", 27, NOW - 1, NOW + 8_000)
        .unwrap();
    let mut carol_match =
        annoda_core::matching::MatchRecord::new(carol_credential.profile_id(), alice_id).unwrap();
    let carol_like = carol_match
        .create_like_envelope(
            &carol_device,
            &carol_credential,
            &alice_credential,
            [33; 16],
            NOW,
            NOW + 2_000,
            &issuers,
        )
        .unwrap();
    let carol_parcel = MailboxParcel::create(
        &carol_like,
        &carol_credential,
        &alice_credential,
        &issuers,
        NOW,
    )
    .unwrap();

    let clock = Arc::new(ManualClock::new(NOW));
    let volunteer_dir = TempDir::new().unwrap();
    let volunteer = PeerNode::start(config(&volunteer_dir, clock.clone()), issuers.clone())
        .await
        .unwrap();
    let address = volunteer.wait_for_listeners().await.unwrap()[0].clone();
    let sender_dir = TempDir::new().unwrap();
    let sender = PeerNode::start(
        NodeConfig {
            bootstrap_peers: vec![annoda_network::BootstrapPeer {
                peer_id: volunteer.peer_id(),
                address: address.clone(),
            }],
            ..config(&sender_dir, clock.clone())
        },
        issuers.clone(),
    )
    .await
    .unwrap();
    sender
        .deposit_parcel(&[volunteer.peer_id()], parcel, 1)
        .await
        .unwrap();
    sender
        .deposit_parcel(&[volunteer.peer_id()], carol_parcel, 1)
        .await
        .unwrap();
    sender.shutdown().await;
    bob_account.lock();
    let alice = vault.unlock(b"sync-test-passphrase").unwrap();

    let state_path = account_dir.path().join("sync-state.sqlite3");
    let transport_dir = account_dir.path().join("transport");
    let context = SyncContext::new(
        alice_credential.clone(),
        issuers,
        state_path.clone(),
        transport_dir,
        vec![SyncPeerAddress {
            peer_id: volunteer.peer_id().to_string(),
            address: address.to_string(),
        }],
    )
    .unwrap();
    let context = context.with_clock(clock.clone());
    let page_budget = SyncBudget {
        max_mailbox_items: 1,
        ..SyncBudget::default()
    };
    let report = sync_once(&alice, context, page_budget.clone(), Default::default())
        .await
        .unwrap();
    assert_eq!(report.status, SyncStatus::BudgetExhausted);
    assert_eq!(report.verified_items, 1);
    assert_eq!(report.new_events.len(), 1);

    let second_page = sync_once(
        &alice,
        SyncContext::new(
            alice_credential.clone(),
            issuer.trusted_issuers(),
            state_path.clone(),
            account_dir.path().join("transport"),
            vec![SyncPeerAddress {
                peer_id: volunteer.peer_id().to_string(),
                address: address.to_string(),
            }],
        )
        .unwrap()
        .with_clock(clock.clone()),
        page_budget.clone(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(second_page.status, SyncStatus::BudgetExhausted);
    assert_eq!(second_page.verified_items, 1);
    assert_eq!(second_page.new_events.len(), 1);
    let completed_scan = sync_once(
        &alice,
        SyncContext::new(
            alice_credential.clone(),
            issuer.trusted_issuers(),
            state_path.clone(),
            account_dir.path().join("transport"),
            vec![SyncPeerAddress {
                peer_id: volunteer.peer_id().to_string(),
                address: address.to_string(),
            }],
        )
        .unwrap()
        .with_clock(clock.clone()),
        page_budget.clone(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(completed_scan.status, SyncStatus::Complete);
    assert_eq!(completed_scan.verified_items, 0);

    let mut state = PeerStorage::open(&state_path, StorageLimits::default()).unwrap();
    assert_eq!(
        state
            .load_match(alice_id, bob_credential.profile_id())
            .unwrap()
            .unwrap()
            .state(),
        annoda_core::matching::MatchState::Incoming
    );
    let pending = state.pending_notifications(alice_id, 64).unwrap();
    assert_eq!(pending.len(), 2);
    for event in pending {
        assert!(
            state
                .acknowledge_notification(alice_id, event.event_id)
                .unwrap()
        );
    }

    let again = sync_once(
        &alice,
        SyncContext::new(
            alice_credential.clone(),
            issuer.trusted_issuers(),
            state_path.clone(),
            account_dir.path().join("transport"),
            vec![SyncPeerAddress {
                peer_id: volunteer.peer_id().to_string(),
                address: address.to_string(),
            }],
        )
        .unwrap()
        .with_clock(clock.clone()),
        page_budget,
        Default::default(),
    )
    .await
    .unwrap();
    assert!(again.new_events.is_empty());
    assert!(
        state
            .pending_notifications(alice_id, 64)
            .unwrap()
            .is_empty()
    );

    // Alice reciprocates after restoring her account. Bob's already-persisted
    // local intent makes the incoming signed like a positive mutual match.
    let (_, local_match_events) = state
        .apply_local_like_with_events(alice_id, bob_id, [92; 16])
        .unwrap();
    assert!(
        local_match_events
            .iter()
            .any(|event| { event.kind == annoda_core::notifications::NotificationKind::NewMatch })
    );
    let mut alice_match = state.load_match(alice_id, bob_id).unwrap().unwrap();
    let reciprocal = alice_match
        .create_like_envelope(
            alice.identity(),
            &alice_credential,
            &bob_credential,
            [92; 16],
            NOW,
            NOW + 1_000,
            &issuer.trusted_issuers(),
        )
        .unwrap();
    let reciprocal_parcel = MailboxParcel::create(
        &reciprocal,
        &alice_credential,
        &bob_credential,
        &issuer.trusted_issuers(),
        NOW,
    )
    .unwrap();
    let alice_sender_dir = TempDir::new().unwrap();
    let alice_sender = PeerNode::start(
        NodeConfig {
            bootstrap_peers: vec![annoda_network::BootstrapPeer {
                peer_id: volunteer.peer_id(),
                address: address.clone(),
            }],
            ..config(&alice_sender_dir, clock.clone())
        },
        issuer.trusted_issuers(),
    )
    .await
    .unwrap();
    alice_sender
        .deposit_parcel(&[volunteer.peer_id()], reciprocal_parcel, 1)
        .await
        .unwrap();
    alice_sender.shutdown().await;

    let bob = bob_vault.unlock(b"bob-sync-passphrase").unwrap();
    let bob_report = sync_once(
        &bob,
        SyncContext::new(
            bob_credential.clone(),
            issuer.trusted_issuers(),
            bob_state_path.clone(),
            bob_account_dir.path().join("transport"),
            vec![SyncPeerAddress {
                peer_id: volunteer.peer_id().to_string(),
                address: address.to_string(),
            }],
        )
        .unwrap()
        .with_clock(clock.clone()),
        SyncBudget::default(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(bob_report.status, SyncStatus::Complete);
    assert!(
        bob_report
            .new_events
            .iter()
            .any(|event| { event.kind == annoda_core::notifications::NotificationKind::NewMatch })
    );
    assert_eq!(
        state.load_match(alice_id, bob_id).unwrap().unwrap().state(),
        annoda_core::matching::MatchState::Matched
    );
    assert_eq!(
        bob_state
            .load_match(bob_id, alice_id)
            .unwrap()
            .unwrap()
            .state(),
        annoda_core::matching::MatchState::Matched
    );

    let alice_match = state.load_match(alice_id, bob_id).unwrap().unwrap();
    let disclosure = alice_match
        .encrypted_disclosure(
            alice.identity(),
            &alice_credential,
            &bob_credential,
            vec![ContactHandle {
                service: ContactService::Telegram,
                value: "@alice".into(),
            }],
            [55; 16],
            NOW,
            NOW + 1_000,
            &issuer.trusted_issuers(),
        )
        .unwrap();
    let contact_parcel = MailboxParcel::create(
        &disclosure,
        &alice_credential,
        &bob_credential,
        &issuer.trusted_issuers(),
        NOW,
    )
    .unwrap();
    let contact_sender_dir = TempDir::new().unwrap();
    let contact_sender = PeerNode::start(
        NodeConfig {
            bootstrap_peers: vec![annoda_network::BootstrapPeer {
                peer_id: volunteer.peer_id(),
                address: address.clone(),
            }],
            ..config(&contact_sender_dir, clock.clone())
        },
        issuer.trusted_issuers(),
    )
    .await
    .unwrap();
    contact_sender
        .deposit_parcel(&[volunteer.peer_id()], contact_parcel, 1)
        .await
        .unwrap();
    contact_sender.shutdown().await;

    let contact_report = sync_once(
        &bob,
        SyncContext::new(
            bob_credential.clone(),
            issuer.trusted_issuers(),
            bob_state_path,
            bob_account_dir.path().join("transport"),
            vec![SyncPeerAddress {
                peer_id: volunteer.peer_id().to_string(),
                address: address.to_string(),
            }],
        )
        .unwrap()
        .with_clock(clock.clone()),
        SyncBudget::default(),
        Default::default(),
    )
    .await
    .unwrap();
    assert_eq!(contact_report.verified_items, 2);
    assert!(contact_report.new_events.is_empty());
    assert_eq!(
        bob_state.incoming_contact_disclosures(bob_id, 100).unwrap()[0].handles[0].value,
        "@alice"
    );
    bob.lock();
    volunteer.shutdown().await;
}
