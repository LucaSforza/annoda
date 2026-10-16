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
