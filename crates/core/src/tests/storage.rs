use super::*;
use crate::{
    identity::{DevelopmentIssuer, DeviceKeyPair},
    protocol::{MessageKind, PhotoManifest},
};

#[test]
fn mailbox_poll_requires_recipient_proof_and_survives_restart() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 10, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 10, 1000)
        .expect("bc");
    let msg = MessageEnvelope::create(
        &alice,
        &ac,
        &bc,
        MessageKind::Like,
        [3; 16],
        20,
        200,
        b"like",
        &trust,
    )
    .expect("msg");
    let parcel = MailboxParcel::create(&msg, &ac, &bc, &trust, 21).expect("parcel");
    let storage = StorageLimits::default();
    let mut db = PeerStorage::open(temp.path(), storage.clone()).expect("open");
    assert!(db.deposit_mailbox(&parcel, 21).expect("deposit"));
    assert!(!db.deposit_mailbox(&parcel, 21).expect("duplicate"));
    let challenge = [8; 32];
    let proof =
        PeerStorage::signed_poll_proof(&bob, bc.profile_id(), challenge, 22).expect("proof");
    let parcels = db
        .poll_mailbox(&bc, &trust, &challenge, &proof, 22, 10)
        .expect("poll");
    assert_eq!(parcels.len(), 1);
    let received = parcels[0].open(&bob, &bc, &trust, 22).expect("open parcel");
    assert_eq!(received.envelope, msg);
    assert!(
        db.poll_mailbox(&bc, &trust, &challenge, b"bad", 22, 10)
            .is_err()
    );
    drop(db);
    let db = PeerStorage::open(temp.path(), storage).expect("reopen");
    assert_eq!(
        db.poll_mailbox(&bc, &trust, &challenge, &proof, 22, 10)
            .expect("poll after restart")
            .len(),
        1
    );
}

#[test]
fn photo_lease_is_owner_scoped_and_expiring() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let owner = DeviceKeyPair::generate().expect("owner");
    let credential = issuer
        .issue_synthetic(&owner, "Ada", 29, 10, 1000)
        .expect("credential");
    let bytes = b"normalized test image";
    let manifest = PhotoManifest::from_bytes(bytes, "image/jpeg").expect("manifest");
    let lease = ContentLease::issue(&owner, &credential, &manifest, 20, 90, &trust).expect("lease");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    let profile = PublicProfile::create(
        &owner,
        credential.clone(),
        vec![manifest.clone()],
        100,
        &trust,
        20,
    )
    .expect("profile");
    db.store_profile(&profile, &trust, 21)
        .expect("profile store");
    db.store_photo(manifest.hash, &lease, bytes, &credential, &trust, 21)
        .expect("store");
    assert_eq!(
        db.get_photo(owner.profile_id(), manifest.hash, &trust, 22)
            .expect("get")
            .as_deref(),
        Some(bytes.as_slice())
    );
    let shortened = PublicProfile::create_revisioned(
        &owner,
        credential.clone(),
        vec![manifest.clone()],
        2,
        80,
        &trust,
        30,
    )
    .expect("updated profile");
    db.store_profile(&shortened, &trust, 30).expect("update");
    assert_eq!(
        db.get_photo(owner.profile_id(), manifest.hash, &trust, 85)
            .expect("profile expired"),
        None
    );
    assert_eq!(
        db.get_photo(owner.profile_id(), manifest.hash, &trust, 90)
            .expect("lease expired"),
        None
    );
}

#[test]
fn invalid_or_expired_like_cannot_change_persisted_match_state() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let mut bob_record = MatchRecord::new(bc.profile_id(), ac.profile_id()).expect("record");
    let expired = bob_record
        .create_like_envelope(&bob, &bc, &ac, [4; 16], 10, 20, &trust)
        .expect("like");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    assert!(
        db.receive_like(&expired, &bc, &alice, &ac, &trust, 20)
            .is_err()
    );
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("state"),
        None
    );

    let valid = bob_record
        .create_like_envelope(&bob, &bc, &ac, [5; 16], 21, 100, &trust)
        .expect("like");
    let mut unsigned = valid.clone();
    unsigned.signature.clear();
    assert!(
        db.receive_like(&unsigned, &bc, &alice, &ac, &trust, 22)
            .is_err()
    );
    let mut tampered = valid.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(
        db.receive_like(&tampered, &bc, &alice, &ac, &trust, 22)
            .is_err()
    );
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("state after invalid messages"),
        None
    );
    let incoming = db
        .receive_like(&valid, &bc, &alice, &ac, &trust, 22)
        .expect("receive");
    assert_eq!(incoming.state(), MatchState::Incoming);
    assert_eq!(
        db.load_peer_credential(ac.profile_id(), bc.profile_id())
            .expect("cached credential"),
        Some(bc.clone())
    );
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("persisted")
            .map(|r| r.state()),
        Some(MatchState::Incoming)
    );
    let duplicate = db
        .receive_like(&valid, &bc, &alice, &ac, &trust, 23)
        .expect("duplicate");
    assert_eq!(duplicate.state(), MatchState::Incoming);
    db.apply_local_like(ac.profile_id(), bc.profile_id(), [6; 16])
        .expect("reciprocate");
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("matched")
            .map(|r| r.state()),
        Some(MatchState::Matched)
    );
    drop(db);
    let db = PeerStorage::open_default(temp.path()).expect("restart");
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("state after restart")
            .map(|r| r.state()),
        Some(MatchState::Matched)
    );
}

#[test]
fn application_credentials_and_operations_survive_reopen_and_ack_idempotently() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 10, 1000)
        .expect("credential");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 10, 1000)
        .expect("credential");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    db.save_credential(ac.profile_id(), &ac, &trust, 20)
        .expect("save bound credential");
    assert!(
        db.save_credential(bc.profile_id(), &ac, &trust, 20)
            .is_err()
    );
    let op = db
        .create_or_get_operation(
            ac.profile_id(),
            OutgoingOperationKind::Publication,
            [7; 32],
            b"immutable signed work".to_vec(),
            vec!["peer-a".into(), "peer-b".into()],
            vec![[1; 32], [2; 32]],
            900,
        )
        .expect("create operation");
    let retry = db
        .create_or_get_operation(
            ac.profile_id(),
            OutgoingOperationKind::Publication,
            [7; 32],
            b"immutable signed work".to_vec(),
            vec!["peer-a".into(), "peer-b".into()],
            vec![[1; 32], [2; 32]],
            900,
        )
        .expect("idempotent retry");
    assert_eq!(retry, op);
    assert!(
        db.create_or_get_operation(
            ac.profile_id(),
            OutgoingOperationKind::Publication,
            [7; 32],
            b"different work".to_vec(),
            vec!["peer-a".into(), "peer-b".into()],
            vec![[1; 32], [2; 32]],
            900,
        )
        .is_err()
    );
    let failed = db
        .record_operation_failure(
            ac.profile_id(),
            op.id,
            "peer-a",
            [1; 32],
            DeliveryFailureKind::Unreachable,
        )
        .expect("persist bounded delivery failure");
    assert_eq!(
        failed.peer_item_acks[0].failure,
        Some(DeliveryFailureKind::Unreachable)
    );
    db.acknowledge_operation_item(ac.profile_id(), op.id, "peer-a", [1; 32], true)
        .expect("first ack");
    assert_eq!(
        db.operation(ac.profile_id(), op.id)
            .expect("recovered operation")
            .expect("operation exists")
            .peer_item_acks[0]
            .failure,
        None
    );
    db.acknowledge_operation_item(ac.profile_id(), op.id, "peer-a", [1; 32], false)
        .expect("negative retry cannot erase accepted ack");
    let partial = db
        .operation(ac.profile_id(), op.id)
        .expect("read op")
        .expect("exists");
    assert_eq!(partial.status, OutgoingOperationStatus::Partial);
    db.acknowledge_operation_item(ac.profile_id(), op.id, "peer-a", [2; 32], true)
        .expect("second item");
    db.acknowledge_operation_item(ac.profile_id(), op.id, "peer-b", [1; 32], true)
        .expect("third item");
    let completed = db
        .acknowledge_operation_item(ac.profile_id(), op.id, "peer-b", [2; 32], true)
        .expect("complete");
    assert_eq!(completed.status, OutgoingOperationStatus::Completed);
    assert_eq!(
        db.acknowledge_operation_item(ac.profile_id(), op.id, "peer-b", [2; 32], true)
            .expect("replayed completed ack"),
        completed
    );
    drop(db);

    let db = PeerStorage::open_default(temp.path()).expect("reopen");
    assert_eq!(
        db.load_credential(ac.profile_id()).expect("credential"),
        Some(ac.clone())
    );
    assert_eq!(
        db.operation(ac.profile_id(), op.id).expect("read op"),
        Some(completed)
    );
    assert_eq!(
        db.pending_operations(ac.profile_id(), 1)
            .expect("bounded pending")
            .len(),
        0
    );
}

#[test]
fn pending_operation_drain_rotates_across_bounded_batches() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let owner = ProfileId([42; 32]);
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    for key in 1u8..=4 {
        db.create_or_get_operation(
            owner,
            OutgoingOperationKind::Like,
            [key; 32],
            vec![key],
            vec!["peer".into()],
            vec![[key; 32]],
            1000,
        )
        .expect("create operation");
    }
    let first = db
        .pending_operations_rotated(owner, 2)
        .expect("first bounded batch");
    let second = db
        .pending_operations_rotated(owner, 2)
        .expect("second bounded batch");
    let ids: std::collections::HashSet<_> = first
        .iter()
        .chain(&second)
        .map(|operation| operation.id)
        .collect();
    assert_eq!(ids.len(), 4);
}

#[test]
fn local_like_and_exact_outgoing_operation_commit_atomically_and_deduplicate() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 10, 1000)
        .expect("credential");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    let created = db
        .create_local_like_operation(
            ac.profile_id(),
            bob.profile_id(),
            [8; 16],
            [9; 32],
            b"exact encrypted parcel".to_vec(),
            vec!["peer-bob".into()],
            20,
            900,
        )
        .expect("commit like");
    assert_eq!(created.status, OutgoingOperationStatus::Pending);
    assert_eq!(
        db.load_match(ac.profile_id(), bob.profile_id())
            .expect("match state")
            .map(|record| record.state()),
        Some(MatchState::Outgoing)
    );
    assert!(
        db.apply_feedback_and_model(ac.profile_id(), bob.profile_id(), true, 20, b"snapshot")
            .expect("train after persisted like")
    );
    assert!(
        !db.apply_feedback_and_model(ac.profile_id(), bob.profile_id(), true, 21, b"duplicate")
            .expect("duplicate feedback is idempotent")
    );
    assert_eq!(
        db.load_preference_model(ac.profile_id())
            .expect("model read")
            .as_deref(),
        Some(b"snapshot".as_slice())
    );
    let retry = db
        .create_local_like_operation(
            ac.profile_id(),
            bob.profile_id(),
            [8; 16],
            [9; 32],
            b"exact encrypted parcel".to_vec(),
            vec!["peer-bob".into()],
            20,
            900,
        )
        .expect("logical retry");
    assert_eq!(retry, created);
    assert!(matches!(
        db.create_local_like_operation(
            ac.profile_id(),
            bob.profile_id(),
            [10; 16],
            [11; 32],
            b"new randomized parcel".to_vec(),
            vec!["peer-bob".into()],
            21,
            900,
        )
        .err(),
        Some(Error::Unauthorized)
    ));
}

#[test]
fn delayed_valid_like_keeps_newest_cached_sender_credential() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 10, 1000)
        .expect("ac");
    let old_bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 10, 1000)
        .expect("old bc");
    let new_bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 20, 1000)
        .expect("new bc");
    let manifest = PhotoManifest::from_bytes(b"photo", "image/jpeg").expect("manifest");
    let profile = PublicProfile::create(
        &bob,
        new_bc.clone(),
        vec![manifest.clone()],
        900,
        &trust,
        21,
    )
    .expect("profile");
    let mut record = MatchRecord::new(old_bc.profile_id(), ac.profile_id()).expect("record");
    let old_envelope = record
        .create_like_envelope(&bob, &old_bc, &ac, [44; 16], 22, 200, &trust)
        .expect("old signed like");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    db.cache_candidate(ac.profile_id(), &profile, &trust, 23)
        .expect("cache newer credential");
    db.save_candidate_embedding(
        ac.profile_id(),
        bob.profile_id(),
        manifest.hash.0,
        1,
        &[0.2, -0.4],
    )
    .expect("cache embedding for verified manifest");
    assert_eq!(
        db.candidate_embedding(ac.profile_id(), bob.profile_id(), manifest.hash.0)
            .expect("load embedding"),
        Some((1, vec![0.2, -0.4]))
    );
    assert!(
        db.save_candidate_embedding(ac.profile_id(), bob.profile_id(), [99; 32], 1, &[0.2])
            .is_err()
    );
    let replacement = PhotoManifest::from_bytes(b"replacement photo", "image/jpeg")
        .expect("replacement manifest");
    let updated_profile = PublicProfile::create_revisioned(
        &bob,
        new_bc.clone(),
        vec![replacement],
        2,
        900,
        &trust,
        24,
    )
    .expect("updated profile");
    db.cache_candidate(ac.profile_id(), &updated_profile, &trust, 24)
        .expect("refresh changed profile");
    assert_eq!(
        db.candidate_embedding(ac.profile_id(), bob.profile_id(), manifest.hash.0)
            .expect("old embedding no longer usable"),
        None
    );
    db.receive_like(&old_envelope, &old_bc, &alice, &ac, &trust, 24)
        .expect("accept still-valid delayed like");
    assert_eq!(
        db.load_peer_credential(ac.profile_id(), old_bc.profile_id())
            .expect("cached credential"),
        Some(new_bc)
    );
}

#[test]
fn inbox_and_match_keyset_pages_reach_records_past_the_first_page() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 10, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 10, 1000)
        .expect("bc");
    let db = PeerStorage::open_default(temp.path()).expect("db");
    for value in 1u8..=70 {
        let peer = ProfileId([value; 32]);
        if peer == ac.profile_id() || peer == bc.profile_id() {
            continue;
        }
        let mut record = MatchRecord::new(ac.profile_id(), peer).expect("record");
        record.block();
        save_match_tx(&db.connection, &record).expect("save blocked match");
    }
    let incoming = MatchRecord::from_persisted(
        ac.profile_id(),
        bc.profile_id(),
        MatchState::Incoming,
        None,
        Some([9; 16]),
    )
    .expect("incoming record");
    save_match_tx(&db.connection, &incoming).expect("save incoming");
    save_peer_credential_tx(&db.connection, ac.profile_id(), &bc, 256 * 1024 * 1024)
        .expect("save sender credential");

    let mut after = None;
    let mut matches = Vec::new();
    let mut inbox = Vec::new();
    loop {
        let page = db
            .match_records_after(ac.profile_id(), after, 16)
            .expect("match page");
        if page.is_empty() {
            break;
        }
        after = page.last().map(MatchRecord::peer);
        matches.extend(page.into_iter().map(|record| record.peer()));
    }
    assert!(matches.contains(&bc.profile_id()));
    let mut after = None;
    loop {
        let page = db
            .incoming_like_records_after(ac.profile_id(), after, 16)
            .expect("inbox page");
        if page.is_empty() {
            break;
        }
        after = page.last().map(|(record, _)| record.peer());
        inbox.extend(page.into_iter().map(|(record, _)| record.peer()));
    }
    assert_eq!(inbox, vec![bc.profile_id()]);
}

#[test]
fn contact_disclosure_pages_reach_more_than_one_page_past_other_matches() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let owner = ProfileId([255; 32]);
    let target_match = [90; 32];
    let db = PeerStorage::open_default(temp.path()).expect("open");
    for value in 1u8..=220 {
        let sender = ProfileId([value; 32]);
        let id = [value; 16];
        let match_id = if value <= 150 { [91; 32] } else { target_match };
        let disclosure = ContactDisclosure {
            match_id,
            sender,
            recipient: owner,
            handles: Vec::new(),
        };
        let data = postcard::to_allocvec(&disclosure).expect("encode disclosure");
        db.connection
            .execute(
                "INSERT INTO incoming_contacts(recipient,sender,id,data) VALUES(?1,?2,?3,?4)",
                params![owner.0.as_slice(), sender.0.as_slice(), id.as_slice(), data],
            )
            .expect("insert disclosure fixture");
    }
    let first = db
        .incoming_contact_disclosures_for_match_page(owner, target_match, None, 64)
        .expect("first page");
    assert_eq!(first.disclosures.len(), 64);
    let cursor = first.next_cursor.expect("next page cursor");
    let second = db
        .incoming_contact_disclosures_for_match_page(owner, target_match, Some(cursor), 64)
        .expect("second page");
    assert_eq!(second.disclosures.len(), 6);
    assert!(second.next_cursor.is_none());
}

#[test]
fn photo_authorization_metadata_counts_against_storage_quota() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let owner = DeviceKeyPair::generate().expect("owner");
    let credential = issuer
        .issue_synthetic(&owner, "Ada", 29, 10, 1000)
        .expect("credential");
    let bytes = b"normalized test image";
    let manifest = PhotoManifest::from_bytes(bytes, "image/jpeg").expect("manifest");
    let lease = ContentLease::issue(&owner, &credential, &manifest, 20, 90, &trust).expect("lease");
    let profile = PublicProfile::create(
        &owner,
        credential.clone(),
        vec![manifest.clone()],
        100,
        &trust,
        20,
    )
    .expect("profile");
    let profile_bytes = postcard::to_allocvec(&profile).expect("profile bytes");
    let limits = StorageLimits {
        max_bytes: profile_bytes.len() as u64 + 48 + bytes.len() as u64 + 32,
        ..StorageLimits::default()
    };
    let mut db = PeerStorage::open(temp.path(), limits).expect("db");
    db.store_profile(&profile, &trust, 21)
        .expect("profile store");
    assert!(matches!(
        db.store_photo(manifest.hash, &lease, bytes, &credential, &trust, 21),
        Err(Error::LimitExceeded)
    ));
}

#[test]
fn notifications_are_stable_owner_scoped_and_explicitly_acknowledged() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let mut bob_record = MatchRecord::new(bc.profile_id(), ac.profile_id()).expect("record");
    let incoming = bob_record
        .create_like_envelope(&bob, &bc, &ac, [21; 16], 2, 100, &trust)
        .expect("like");
    let mut alice_db = PeerStorage::open_default(temp.path()).expect("db");
    alice_db
        .receive_like(&incoming, &bc, &alice, &ac, &trust, 3)
        .expect("receive");
    let alice_events = alice_db
        .pending_notifications(ac.profile_id(), 64)
        .expect("events");
    assert_eq!(alice_events.len(), 1);
    assert_eq!(alice_events[0].kind, NotificationKind::NewLike);
    let stable_id = alice_events[0].event_id;
    assert_eq!(
        alice_db
            .pending_notifications(ac.profile_id(), 64)
            .expect("replay")[0]
            .event_id,
        stable_id
    );
    assert!(
        !alice_db
            .acknowledge_notification(bc.profile_id(), stable_id)
            .expect("wrong owner")
    );
    assert!(
        alice_db
            .acknowledge_notification(ac.profile_id(), stable_id)
            .expect("ack")
    );
    assert!(
        !alice_db
            .acknowledge_notification(ac.profile_id(), stable_id)
            .expect("idempotent ack")
    );
    drop(alice_db);
    let mut alice_db = PeerStorage::open_default(temp.path()).expect("reopen");
    assert!(
        alice_db
            .pending_notifications(ac.profile_id(), 64)
            .expect("after ack")
            .is_empty()
    );
    let duplicate = alice_db
        .receive_like(&incoming, &bc, &alice, &ac, &trust, 4)
        .expect("redelivery after ack");
    assert_eq!(duplicate.state(), MatchState::Incoming);
    assert!(
        alice_db
            .pending_notifications(ac.profile_id(), 64)
            .expect("acknowledged event stays absent")
            .is_empty()
    );
}

#[test]
fn notification_preferences_suppress_events_without_suppressing_match_state() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let mut bob_record = MatchRecord::new(bc.profile_id(), ac.profile_id()).expect("record");
    let incoming = bob_record
        .create_like_envelope(&bob, &bc, &ac, [22; 16], 2, 100, &trust)
        .expect("like");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    db.set_notification_preferences(
        ac.profile_id(),
        NotificationPreferences {
            likes_enabled: false,
            matches_enabled: true,
        },
    )
    .expect("prefs");
    db.receive_like(&incoming, &bc, &alice, &ac, &trust, 3)
        .expect("receive");
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("state")
            .map(|r| r.state()),
        Some(MatchState::Incoming)
    );
    assert!(
        db.pending_notifications(ac.profile_id(), 64)
            .expect("none")
            .is_empty()
    );
}

#[test]
fn notification_and_checkpoint_rollback_with_failed_outbox_insert() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let mut bob_record = MatchRecord::new(bc.profile_id(), ac.profile_id()).expect("record");
    let incoming = bob_record
        .create_like_envelope(&bob, &bc, &ac, [23; 16], 2, 100, &trust)
        .expect("like");
    let cursor = MailboxCursor {
        expires_at: 100,
        parcel_id: [9; 16],
    };
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    db.connection.execute_batch(
            "CREATE TRIGGER fail_notification BEFORE INSERT ON notification_outbox BEGIN SELECT RAISE(ABORT, 'test failure'); END;",
        ).expect("trigger");
    assert!(
        db.receive_like_checkpointed(&incoming, &bc, &alice, &ac, &trust, 3, "peer-a", cursor)
            .is_err()
    );
    assert!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("state")
            .is_none()
    );
    assert!(
        db.load_mailbox_checkpoint(ac.profile_id(), "peer-a")
            .expect("checkpoint")
            .is_none()
    );
    db.connection
        .execute_batch("DROP TRIGGER fail_notification;")
        .expect("drop trigger");
    let (record, events) = db
        .receive_like_checkpointed(&incoming, &bc, &alice, &ac, &trust, 3, "peer-a", cursor)
        .expect("retry");
    assert_eq!(record.state(), MatchState::Incoming);
    assert_eq!(events.len(), 1);
    assert_eq!(
        db.load_mailbox_checkpoint(ac.profile_id(), "peer-a")
            .expect("checkpoint"),
        Some(cursor)
    );
}

#[test]
fn paged_mailbox_uses_stable_expiry_id_cursor() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    for id in [[1; 16], [2; 16]] {
        let msg = MessageEnvelope::create(
            &alice,
            &ac,
            &bc,
            MessageKind::Like,
            id,
            2,
            100,
            b"like",
            &trust,
        )
        .expect("message");
        db.deposit_mailbox(
            &MailboxParcel::create(&msg, &ac, &bc, &trust, 3).expect("parcel"),
            3,
        )
        .expect("deposit");
    }
    let challenge = [7; 32];
    let proof = PeerStorage::signed_poll_proof(&bob, bc.profile_id(), challenge, 4).expect("proof");
    let first = db
        .poll_mailbox_page(&bc, &trust, &challenge, &proof, 4, 4, None, 1)
        .expect("first page");
    assert_eq!(first.parcels.len(), 1);
    assert!(!first.completed);
    let second = db
        .poll_mailbox_page(&bc, &trust, &challenge, &proof, 4, 4, first.next_cursor, 1)
        .expect("second page");
    assert_eq!(second.parcels.len(), 1);
    assert_ne!(first.parcels[0].id, second.parcels[0].id);
    let end = db
        .poll_mailbox_page(&bc, &trust, &challenge, &proof, 4, 4, second.next_cursor, 1)
        .expect("end page");
    assert!(end.parcels.is_empty());
    assert!(end.completed);
}

#[test]
fn disabled_match_event_is_not_created_by_replaying_an_old_local_like() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let mut bob_record = MatchRecord::new(bc.profile_id(), ac.profile_id()).expect("record");
    let incoming = bob_record
        .create_like_envelope(&bob, &bc, &ac, [24; 16], 2, 100, &trust)
        .expect("like");
    let mut db = PeerStorage::open_default(temp.path()).expect("db");
    db.receive_like(&incoming, &bc, &alice, &ac, &trust, 3)
        .expect("receive");
    db.set_notification_preferences(
        ac.profile_id(),
        NotificationPreferences {
            likes_enabled: false,
            matches_enabled: false,
        },
    )
    .expect("disable match notices");
    let (_, events) = db
        .apply_local_like_with_events(ac.profile_id(), bc.profile_id(), [25; 16])
        .expect("reciprocate");
    assert!(events.is_empty());
    db.set_notification_preferences(
        ac.profile_id(),
        NotificationPreferences {
            likes_enabled: false,
            matches_enabled: true,
        },
    )
    .expect("enable match notices");
    let (_, events) = db
        .apply_local_like_with_events(ac.profile_id(), bc.profile_id(), [25; 16])
        .expect("repeat");
    assert!(events.is_empty());
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("matched")
            .map(|record| record.state()),
        Some(MatchState::Matched)
    );
    assert!(
        db.pending_notifications(ac.profile_id(), 64)
            .expect("no stale event")
            .is_empty()
    );
}

#[test]
fn opening_m1_sqlite_preserves_profile_match_and_mailbox_records() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let profile =
        PublicProfile::create(&alice, ac.clone(), Vec::new(), 500, &trust, 2).expect("profile");
    let like = MessageEnvelope::create(
        &bob,
        &bc,
        &ac,
        MessageKind::Like,
        [31; 16],
        3,
        200,
        b"opaque",
        &trust,
    )
    .expect("message");
    let parcel = MailboxParcel::create(&like, &bc, &ac, &trust, 4).expect("parcel");

    let old = Connection::open(temp.path()).expect("old schema");
    old.execute_batch(
            "CREATE TABLE profiles (id BLOB PRIMARY KEY NOT NULL, data BLOB NOT NULL, expires_at INTEGER NOT NULL, revision INTEGER NOT NULL);
             CREATE TABLE mailbox (id BLOB NOT NULL, recipient BLOB NOT NULL, expires_at INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id,recipient));
             CREATE TABLE match_state (owner BLOB NOT NULL, peer BLOB NOT NULL, state INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(owner,peer));",
        )
        .expect("old tables");
    let profile_data = postcard::to_allocvec(&profile).expect("profile data");
    let parcel_data = postcard::to_allocvec(&parcel).expect("parcel data");
    let match_data = postcard::to_allocvec(&PersistedMatch {
        owner: ac.profile_id(),
        peer: bc.profile_id(),
        state: MatchState::Incoming,
        local_like_id: None,
        remote_like_id: Some([32; 16]),
    })
    .expect("match data");
    old.execute(
        "INSERT INTO profiles(id,data,expires_at,revision) VALUES(?1,?2,?3,?4)",
        params![ac.profile_id().0.as_slice(), profile_data, 500i64, 1i64],
    )
    .expect("old profile");
    old.execute(
        "INSERT INTO mailbox(id,recipient,expires_at,data) VALUES(?1,?2,?3,?4)",
        params![
            parcel.id.as_slice(),
            ac.profile_id().0.as_slice(),
            200i64,
            parcel_data
        ],
    )
    .expect("old parcel");
    old.execute(
        "INSERT INTO match_state(owner,peer,state,data) VALUES(?1,?2,2,?3)",
        params![
            ac.profile_id().0.as_slice(),
            bc.profile_id().0.as_slice(),
            match_data
        ],
    )
    .expect("old match");
    drop(old);

    let db = PeerStorage::open_default(temp.path()).expect("M2 open");
    assert!(
        db.get_profile(ac.profile_id(), &trust, 5)
            .expect("profile survives")
            .is_some()
    );
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("match survives")
            .map(|record| record.state()),
        Some(MatchState::Incoming)
    );
    let challenge = [33; 32];
    let proof =
        PeerStorage::signed_poll_proof(&alice, ac.profile_id(), challenge, 5).expect("poll proof");
    let parcels = db
        .poll_mailbox(&ac, &trust, &challenge, &proof, 5, 1)
        .expect("mailbox survives");
    assert_eq!(parcels.len(), 1);
    assert_eq!(parcels[0].id, parcel.id);
    assert!(
        db.pending_notifications(ac.profile_id(), 64)
            .expect("new outbox")
            .is_empty()
    );
}

#[test]
fn opening_m2_sqlite_preserves_notifications_preferences_checkpoints_and_records() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let alice = DeviceKeyPair::generate().expect("alice");
    let bob = DeviceKeyPair::generate().expect("bob");
    let ac = issuer
        .issue_synthetic(&alice, "Alice", 24, 1, 1000)
        .expect("ac");
    let bc = issuer
        .issue_synthetic(&bob, "Bob", 24, 1, 1000)
        .expect("bc");
    let profile =
        PublicProfile::create(&alice, ac.clone(), Vec::new(), 500, &trust, 2).expect("profile");
    let like = MessageEnvelope::create(
        &bob,
        &bc,
        &ac,
        MessageKind::Like,
        [41; 16],
        3,
        200,
        b"opaque M2 parcel",
        &trust,
    )
    .expect("message");
    let parcel = MailboxParcel::create(&like, &bc, &ac, &trust, 4).expect("parcel");
    let pending_event_id = [42; 32];
    let acknowledged_event_id = [43; 32];
    let saved_checkpoint = MailboxCursor {
        expires_at: 700,
        parcel_id: [44; 16],
    };

    // Literal pre-M3 M2 schema: opening the database under M3 must only add its app tables.
    let old = Connection::open(temp.path()).expect("M2 database");
    old.execute_batch(
        "CREATE TABLE profiles (id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=32), data BLOB NOT NULL, expires_at INTEGER NOT NULL, revision INTEGER NOT NULL);
         CREATE TABLE blobs (hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash)=32), data BLOB NOT NULL);
         CREATE TABLE photo_leases (owner BLOB NOT NULL CHECK(length(owner)=32), hash BLOB NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE, expires_at INTEGER NOT NULL, authorization BLOB NOT NULL, PRIMARY KEY(owner,hash));
         CREATE TABLE mailbox (id BLOB NOT NULL CHECK(length(id)=16), recipient BLOB NOT NULL CHECK(length(recipient)=32), expires_at INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id,recipient));
         CREATE TABLE seen_messages (id BLOB NOT NULL CHECK(length(id)=16), recipient BLOB NOT NULL CHECK(length(recipient)=32), expires_at INTEGER NOT NULL, PRIMARY KEY(id,recipient));
         CREATE TABLE match_state (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), state INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(owner,peer));
         CREATE TABLE processed_likes (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), PRIMARY KEY(recipient,sender,id));
         CREATE TABLE notification_preferences (owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner)=32), likes_enabled INTEGER NOT NULL CHECK(likes_enabled IN (0,1)), matches_enabled INTEGER NOT NULL CHECK(matches_enabled IN (0,1)));
         CREATE TABLE notification_outbox (owner BLOB NOT NULL CHECK(length(owner)=32), event_id BLOB NOT NULL CHECK(length(event_id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2)), acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)), PRIMARY KEY(owner,event_id));
         CREATE INDEX notification_pending ON notification_outbox(owner,acknowledged,kind);
         CREATE TABLE sync_checkpoints (owner BLOB NOT NULL CHECK(length(owner)=32), peer TEXT NOT NULL, expires_at INTEGER NOT NULL, parcel_id BLOB NOT NULL CHECK(length(parcel_id)=16), PRIMARY KEY(owner,peer));
         CREATE TABLE sync_rejections (owner BLOB NOT NULL CHECK(length(owner)=32), peer TEXT NOT NULL, expires_at INTEGER NOT NULL, parcel_id BLOB NOT NULL CHECK(length(parcel_id)=16), PRIMARY KEY(owner,peer,expires_at,parcel_id));
         CREATE TABLE processed_contacts (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), PRIMARY KEY(recipient,sender,id));
         CREATE TABLE incoming_contacts (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), data BLOB NOT NULL, PRIMARY KEY(recipient,sender,id));",
    )
    .expect("M2 tables");
    let profile_data = postcard::to_allocvec(&profile).expect("profile data");
    let parcel_data = postcard::to_allocvec(&parcel).expect("parcel data");
    let match_data = postcard::to_allocvec(&PersistedMatch {
        owner: ac.profile_id(),
        peer: bc.profile_id(),
        state: MatchState::Incoming,
        local_like_id: None,
        remote_like_id: Some([45; 16]),
    })
    .expect("match data");
    old.execute(
        "INSERT INTO profiles(id,data,expires_at,revision) VALUES(?1,?2,?3,?4)",
        params![ac.profile_id().0.as_slice(), profile_data, 500i64, 1i64],
    )
    .expect("old profile");
    old.execute(
        "INSERT INTO mailbox(id,recipient,expires_at,data) VALUES(?1,?2,?3,?4)",
        params![
            parcel.id.as_slice(),
            ac.profile_id().0.as_slice(),
            200i64,
            parcel_data
        ],
    )
    .expect("old parcel");
    old.execute(
        "INSERT INTO match_state(owner,peer,state,data) VALUES(?1,?2,2,?3)",
        params![
            ac.profile_id().0.as_slice(),
            bc.profile_id().0.as_slice(),
            match_data
        ],
    )
    .expect("old match");
    old.execute(
        "INSERT INTO notification_preferences(owner,likes_enabled,matches_enabled) VALUES(?1,0,1)",
        [ac.profile_id().0.as_slice()],
    )
    .expect("old notification preferences");
    old.execute(
        "INSERT INTO notification_outbox(owner,event_id,kind,acknowledged) VALUES(?1,?2,2,0), (?1,?3,1,1)",
        params![
            ac.profile_id().0.as_slice(),
            pending_event_id.as_slice(),
            acknowledged_event_id.as_slice()
        ],
    )
    .expect("old notification events");
    old.execute(
        "INSERT INTO sync_checkpoints(owner,peer,expires_at,parcel_id) VALUES(?1,?2,?3,?4)",
        params![
            ac.profile_id().0.as_slice(),
            "legacy-peer",
            saved_checkpoint.expires_at as i64,
            saved_checkpoint.parcel_id.as_slice()
        ],
    )
    .expect("old sync checkpoint");
    drop(old);

    let mut db = PeerStorage::open_default(temp.path()).expect("M2 open");
    db.bind_application_owner(ac.profile_id())
        .expect("opt legacy DB into M3 account ownership");
    db.save_credential(ac.profile_id(), &ac, &trust, 5)
        .expect("write M3 application credential");
    assert_eq!(
        db.load_credential(ac.profile_id()).expect("M3 credential"),
        Some(ac.clone())
    );
    assert!(
        db.get_profile(ac.profile_id(), &trust, 5)
            .expect("profile survives")
            .is_some()
    );
    assert_eq!(
        db.load_match(ac.profile_id(), bc.profile_id())
            .expect("match survives")
            .map(|record| record.state()),
        Some(MatchState::Incoming)
    );
    assert_eq!(
        db.notification_preferences(ac.profile_id())
            .expect("preferences survive"),
        NotificationPreferences {
            likes_enabled: false,
            matches_enabled: true,
        }
    );
    assert_eq!(
        db.pending_notifications(ac.profile_id(), 64)
            .expect("pending event survives"),
        vec![NotificationEvent {
            event_id: pending_event_id,
            kind: NotificationKind::NewMatch,
        }]
    );
    assert!(
        !db.acknowledge_notification(ac.profile_id(), acknowledged_event_id)
            .expect("already-acknowledged event remains acknowledged")
    );
    assert_eq!(
        db.load_mailbox_checkpoint(ac.profile_id(), "legacy-peer")
            .expect("checkpoint survives"),
        Some(saved_checkpoint)
    );
    let challenge = [46; 32];
    let proof =
        PeerStorage::signed_poll_proof(&alice, ac.profile_id(), challenge, 5).expect("poll proof");
    let parcels = db
        .poll_mailbox(&ac, &trust, &challenge, &proof, 5, 1)
        .expect("mailbox survives");
    assert_eq!(parcels.len(), 1);
    assert_eq!(parcels[0].id, parcel.id);
}

#[test]
fn sync_storage_lock_wait_uses_the_caller_deadline_bound() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let issuer = DevelopmentIssuer::new().expect("issuer");
    let trust = issuer.trusted_issuers();
    let owner = DeviceKeyPair::generate().expect("owner");
    let credential = issuer
        .issue_synthetic(&owner, "Ada", 29, 1, 1000)
        .expect("credential");
    let profile =
        PublicProfile::create(&owner, credential, Vec::new(), 500, &trust, 2).expect("profile");
    drop(PeerStorage::open_default(temp.path()).expect("initialize database"));
    let blocker = Connection::open(temp.path()).expect("blocker");
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("hold database write lock");

    let mut client = PeerStorage::open_with_busy_timeout(
        temp.path(),
        StorageLimits::default(),
        Duration::from_millis(20),
    )
    .expect("open with bounded lock wait");
    let started = std::time::Instant::now();
    let result = client.store_profile(&profile, &trust, 3);
    assert!(matches!(result, Err(Error::Storage(_))));
    assert!(started.elapsed() < Duration::from_millis(500));
    blocker.execute_batch("ROLLBACK;").expect("release lock");
}

#[test]
fn expire_reclaims_only_expired_rejection_markers() {
    let temp = tempfile::NamedTempFile::new().expect("db path");
    let owner = DeviceKeyPair::generate().expect("owner").profile_id();
    let mut db = PeerStorage::open_default(temp.path()).expect("open");
    db.mark_mailbox_rejected(
        owner,
        "peer-a",
        MailboxCursor {
            expires_at: 10,
            parcel_id: [1; 16],
        },
    )
    .expect("expired rejection");
    db.mark_mailbox_rejected(
        owner,
        "peer-a",
        MailboxCursor {
            expires_at: 30,
            parcel_id: [2; 16],
        },
    )
    .expect("live rejection");

    db.expire(10).expect("expire old rows");

    let count: u32 = db
        .connection
        .query_row(
            "SELECT count(*) FROM sync_rejections WHERE owner=?1",
            [owner.0.as_slice()],
            |row| row.get(0),
        )
        .expect("remaining rejection count");
    assert_eq!(count, 1);
    assert_eq!(
        db.load_mailbox_checkpoint(owner, "peer-a")
            .expect("checkpoint remains")
            .map(|cursor| cursor.parcel_id),
        Some([2; 16])
    );
}
