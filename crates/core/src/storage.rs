use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    identity::{DeviceKeyPair, TrustedIssuers, VerifiedCredential, canonical, verify_signature},
    matching::{ContactDisclosure, MatchRecord, MatchState},
    protocol::{
        ContentHash, ContentLease, MailboxParcel, MessageEnvelope, MessageKind, PhotoManifest,
        ProfileId, PublicProfile,
    },
};

pub use crate::notifications::{NotificationEvent, NotificationKind, NotificationPreferences};

const POLL_DOMAIN: &[u8] = b"annoda/mailbox-poll/v1\0";
const MAX_NOTIFICATION_EVENTS_PER_OWNER: u32 = 4096;
const MAX_NOTIFICATION_HISTORY_PER_OWNER: u32 = 4096;
const MAX_CHECKPOINT_PEER_ID_BYTES: usize = 256;
const MAX_SYNC_REJECTIONS_PER_OWNER: u32 = 8192;
const MAX_OPERATIONS_PER_OWNER: u32 = 1024;
const MAX_PENDING_OPERATIONS_PER_OWNER: u32 = 256;
const MAX_OPERATION_BYTES: usize = 24 * 1024 * 1024 + 64 * 1024;
const MAX_OPERATION_PEERS: usize = 64;
const MAX_OPERATION_ITEMS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OutgoingOperationKind {
    Publication,
    Like,
    Contact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OutgoingOperationStatus {
    Pending,
    Partial,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeliveryFailureKind {
    Unreachable,
    Rejected,
    Budget,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerItemAck {
    pub peer_id: String,
    pub item: [u8; 32],
    pub accepted: bool,
    pub failure: Option<DeliveryFailureKind>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: [u8; 16],
    pub owner: ProfileId,
    pub kind: OutgoingOperationKind,
    pub idempotency_key: [u8; 32],
    pub related_peer: Option<ProfileId>,
    pub version: u16,
    pub exact_payload: Vec<u8>,
    pub peer_targets: Vec<String>,
    pub items: Vec<[u8; 32]>,
    pub peer_item_acks: Vec<PeerItemAck>,
    pub expires_at: u64,
    pub status: OutgoingOperationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocalReportRecord {
    pub report_id: [u8; 16],
    pub created_at: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactDisclosurePage {
    pub disclosures: Vec<ContactDisclosure>,
    pub next_cursor: Option<(ProfileId, [u8; 16])>,
}

#[derive(Clone, Debug)]
pub struct StorageLimits {
    pub max_bytes: u64,
    pub max_mailbox_messages: u32,
    pub max_messages_per_recipient: u32,
}
impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            max_mailbox_messages: 10_000,
            max_messages_per_recipient: 256,
        }
    }
}

pub struct PeerStorage {
    connection: Connection,
    limits: StorageLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxCursor {
    pub expires_at: u64,
    pub parcel_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxPage {
    pub parcels: Vec<MailboxParcel>,
    pub next_cursor: Option<MailboxCursor>,
    pub completed: bool,
}

#[derive(Serialize)]
struct PollClaims {
    recipient: ProfileId,
    challenge: [u8; 32],
    now: u64,
}

#[derive(Serialize, Deserialize)]
struct PersistedMatch {
    owner: ProfileId,
    peer: ProfileId,
    state: MatchState,
    local_like_id: Option<[u8; 16]>,
    remote_like_id: Option<[u8; 16]>,
}

impl PeerStorage {
    pub fn open(path: impl AsRef<Path>, limits: StorageLimits) -> Result<Self> {
        Self::open_with_busy_timeout(path, limits, Duration::from_secs(5))
    }

    /// Opens client storage with a bounded SQLite lock wait for finite sync sessions.
    pub fn open_with_busy_timeout(
        path: impl AsRef<Path>,
        limits: StorageLimits,
        busy_timeout: Duration,
    ) -> Result<Self> {
        if busy_timeout > Duration::from_secs(5) {
            return Err(Error::InvalidInput);
        }
        let connection = Connection::open(path)?;
        connection.busy_timeout(busy_timeout)?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS profiles (id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=32), data BLOB NOT NULL, expires_at INTEGER NOT NULL, revision INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS blobs (hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash)=32), data BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS photo_leases (owner BLOB NOT NULL CHECK(length(owner)=32), hash BLOB NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE, expires_at INTEGER NOT NULL, authorization BLOB NOT NULL, PRIMARY KEY(owner,hash));
             CREATE TABLE IF NOT EXISTS mailbox (id BLOB NOT NULL CHECK(length(id)=16), recipient BLOB NOT NULL CHECK(length(recipient)=32), expires_at INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id,recipient));
             CREATE INDEX IF NOT EXISTS mailbox_recipient_expiry ON mailbox(recipient, expires_at);
             CREATE TABLE IF NOT EXISTS seen_messages (id BLOB NOT NULL CHECK(length(id)=16), recipient BLOB NOT NULL CHECK(length(recipient)=32), expires_at INTEGER NOT NULL, PRIMARY KEY(id,recipient));
             CREATE TABLE IF NOT EXISTS match_state (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), state INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS processed_likes (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), PRIMARY KEY(recipient,sender,id));
             CREATE TABLE IF NOT EXISTS notification_preferences (owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner)=32), likes_enabled INTEGER NOT NULL CHECK(likes_enabled IN (0,1)), matches_enabled INTEGER NOT NULL CHECK(matches_enabled IN (0,1)));
             CREATE TABLE IF NOT EXISTS notification_outbox (owner BLOB NOT NULL CHECK(length(owner)=32), event_id BLOB NOT NULL CHECK(length(event_id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2)), acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)), PRIMARY KEY(owner,event_id));
             CREATE INDEX IF NOT EXISTS notification_pending ON notification_outbox(owner,acknowledged,kind);
             CREATE TABLE IF NOT EXISTS sync_checkpoints (owner BLOB NOT NULL CHECK(length(owner)=32), peer TEXT NOT NULL, expires_at INTEGER NOT NULL, parcel_id BLOB NOT NULL CHECK(length(parcel_id)=16), PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS sync_rejections (owner BLOB NOT NULL CHECK(length(owner)=32), peer TEXT NOT NULL, expires_at INTEGER NOT NULL, parcel_id BLOB NOT NULL CHECK(length(parcel_id)=16), PRIMARY KEY(owner,peer,expires_at,parcel_id));
             CREATE TABLE IF NOT EXISTS processed_contacts (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), PRIMARY KEY(recipient,sender,id));
             CREATE TABLE IF NOT EXISTS incoming_contacts (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), data BLOB NOT NULL, PRIMARY KEY(recipient,sender,id));"
        )?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_credentials (owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner)=32), data BLOB NOT NULL CHECK(length(data)<=16384));
             CREATE TABLE IF NOT EXISTS peer_credentials (owner BLOB NOT NULL CHECK(length(owner)=32), subject BLOB NOT NULL CHECK(length(subject)=32), data BLOB NOT NULL CHECK(length(data)<=16384), PRIMARY KEY(owner,subject));
             CREATE TABLE IF NOT EXISTS local_feedback (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), liked INTEGER NOT NULL CHECK(liked IN (0,1)), seen_at INTEGER NOT NULL, PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS trained_feedback (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), liked INTEGER NOT NULL CHECK(liked IN (0,1)), PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS candidate_cache (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), data BLOB NOT NULL CHECK(length(data)<=16384), cached_at INTEGER NOT NULL, PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS candidate_embeddings (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), source_hash BLOB NOT NULL CHECK(length(source_hash)=32), version INTEGER NOT NULL CHECK(version BETWEEN 0 AND 65535), data BLOB NOT NULL CHECK(length(data)<=32768), PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS local_reports (owner BLOB NOT NULL CHECK(length(owner)=32), report_id BLOB NOT NULL CHECK(length(report_id)=16), data BLOB NOT NULL CHECK(length(data)<=2048), created_at INTEGER NOT NULL, PRIMARY KEY(owner,report_id));
             CREATE TABLE IF NOT EXISTS preference_models (owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner)=32), data BLOB NOT NULL CHECK(length(data)<=65536));
             CREATE TABLE IF NOT EXISTS application_owner (singleton INTEGER PRIMARY KEY CHECK(singleton=1), owner BLOB NOT NULL CHECK(length(owner)=32));
             CREATE TABLE IF NOT EXISTS outgoing_operations (id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16), owner BLOB NOT NULL CHECK(length(owner)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3)), idempotency_key BLOB NOT NULL CHECK(length(idempotency_key)=32), version INTEGER NOT NULL CHECK(version=1), related_peer BLOB CHECK(related_peer IS NULL OR length(related_peer)=32), exact_payload BLOB NOT NULL, peer_targets BLOB NOT NULL, items BLOB NOT NULL, expires_at INTEGER NOT NULL, status INTEGER NOT NULL CHECK(status IN (0,1,2,3)), UNIQUE(owner,kind,idempotency_key));
             CREATE TABLE IF NOT EXISTS operation_drain_cursor (owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner)=32), operation_id BLOB NOT NULL CHECK(length(operation_id)=16));
             CREATE INDEX IF NOT EXISTS outgoing_owner_status ON outgoing_operations(owner,status,id);
             CREATE TABLE IF NOT EXISTS operation_item_acks (operation_id BLOB NOT NULL REFERENCES outgoing_operations(id) ON DELETE CASCADE, peer_id TEXT NOT NULL, item BLOB NOT NULL CHECK(length(item)=32), accepted INTEGER NOT NULL CHECK(accepted IN (0,1)), PRIMARY KEY(operation_id,peer_id,item));
             CREATE TABLE IF NOT EXISTS operation_item_failures (operation_id BLOB NOT NULL, peer_id TEXT NOT NULL, item BLOB NOT NULL CHECK(length(item)=32), reason INTEGER NOT NULL CHECK(reason BETWEEN 1 AND 4), PRIMARY KEY(operation_id,peer_id,item), FOREIGN KEY(operation_id,peer_id,item) REFERENCES operation_item_acks(operation_id,peer_id,item) ON DELETE CASCADE);"
        )?;
        Ok(Self { connection, limits })
    }

    pub fn open_default(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path, StorageLimits::default())
    }

    /// Opts this database into single-account M3 ownership; legacy M2 storage stays unbound.
    pub fn bind_application_owner(&mut self, owner: ProfileId) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT owner FROM application_owner WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if existing.as_slice() != owner.0.as_slice() => {
                return Err(Error::Unauthorized);
            }
            Some(_) => {}
            None => {
                tx.execute(
                    "INSERT INTO application_owner(singleton,owner) VALUES(1,?1)",
                    [owner.0.as_slice()],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn store_profile(
        &mut self,
        profile: &PublicProfile,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<()> {
        profile.verify(issuers, now)?;
        let expires_at = sql_u64(profile.expires_at)?;
        let revision_sql = sql_u64(profile.revision)?;
        let data = postcard::to_allocvec(profile).map_err(|_| Error::Serialization)?;
        if data.len() > 16 * 1024 {
            return Err(Error::LimitExceeded);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT revision,data FROM profiles WHERE id=?1",
                [profile.owner.0.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((revision, old_data)) = old {
            let revision = u64::try_from(revision).map_err(|_| Error::InvalidInput)?;
            if revision > profile.revision {
                return Err(Error::Unauthorized);
            }
            if revision == profile.revision {
                return if old_data == data {
                    Ok(())
                } else {
                    Err(Error::Unauthorized)
                };
            }
            if storage_bytes(&tx)?.saturating_sub(old_data.len() as u64 + 48)
                + data.len() as u64
                + 48
                > self.limits.max_bytes
            {
                return Err(Error::LimitExceeded);
            }
        } else if storage_bytes(&tx)? + data.len() as u64 + 48 > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        tx.execute("INSERT INTO profiles(id,data,expires_at,revision) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET data=excluded.data, expires_at=excluded.expires_at, revision=excluded.revision", params![profile.owner.0.as_slice(), data, expires_at, revision_sql])?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_profile(
        &self,
        id: ProfileId,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Option<PublicProfile>> {
        let now_sql = sql_u64(now)?;
        let row: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT data FROM profiles WHERE id=?1 AND expires_at>?2",
                params![id.0.as_slice(), now_sql],
                |r| r.get(0),
            )
            .optional()?;
        let Some(data) = row else {
            return Ok(None);
        };
        let profile: PublicProfile =
            postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
        profile.verify(issuers, now)?;
        Ok(Some(profile))
    }

    pub fn latest_profile_revision(&self, owner: ProfileId) -> Result<Option<u64>> {
        let revision: Option<i64> = self
            .connection
            .query_row(
                "SELECT revision FROM profiles WHERE id=?1",
                [owner.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        revision
            .map(|value| u64::try_from(value).map_err(|_| Error::InvalidInput))
            .transpose()
    }

    /// Stores a credential only for the account whose signing key it attests.
    pub fn save_credential(
        &mut self,
        owner: ProfileId,
        credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<()> {
        credential.verify(issuers, now)?;
        if credential.profile_id() != owner {
            return Err(Error::Unauthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        save_credential_tx(&tx, owner, credential, self.limits.max_bytes)?;
        tx.commit()?;
        Ok(())
    }

    /// Loads the minimized signed credential; callers revalidate trust and expiry for use.
    pub fn load_credential(&self, owner: ProfileId) -> Result<Option<VerifiedCredential>> {
        load_credential_tx(&self.connection, owner)
    }

    pub fn load_peer_credential(
        &self,
        owner: ProfileId,
        subject: ProfileId,
    ) -> Result<Option<VerifiedCredential>> {
        load_peer_credential_tx(&self.connection, owner, subject)
    }

    // The explicit fields keep the durable operation contract visible at call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn create_or_get_operation(
        &mut self,
        owner: ProfileId,
        kind: OutgoingOperationKind,
        idempotency_key: [u8; 32],
        exact_payload: Vec<u8>,
        peer_targets: Vec<String>,
        items: Vec<[u8; 32]>,
        expires_at: u64,
    ) -> Result<OperationRecord> {
        validate_operation_inputs(
            idempotency_key,
            &exact_payload,
            &peer_targets,
            &items,
            expires_at,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = find_operation_by_key(&tx, owner, kind, idempotency_key)? {
            if existing.exact_payload != exact_payload
                || existing.peer_targets != peer_targets
                || existing.items != items
                || existing.expires_at != expires_at
            {
                return Err(Error::Unauthorized);
            }
            tx.commit()?;
            return Ok(existing);
        }
        let record = insert_operation_tx(
            &tx,
            owner,
            kind,
            idempotency_key,
            None,
            exact_payload,
            peer_targets,
            items,
            expires_at,
            self.limits.max_bytes,
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Commits the positive match transition, notification and exact retry payload together.
    // This transaction must receive the complete signed work and matching context together.
    #[allow(clippy::too_many_arguments)]
    pub fn create_local_like_operation(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        like_id: [u8; 16],
        idempotency_key: [u8; 32],
        exact_payload: Vec<u8>,
        peer_targets: Vec<String>,
        now: u64,
        expires_at: u64,
    ) -> Result<OperationRecord> {
        let items = [*blake3::hash(&exact_payload).as_bytes()].to_vec();
        validate_operation_inputs(
            idempotency_key,
            &exact_payload,
            &peer_targets,
            &items,
            expires_at,
        )?;
        if like_id == [0; 16] || peer == owner {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            find_operation_by_key(&tx, owner, OutgoingOperationKind::Like, idempotency_key)?
        {
            if existing.exact_payload != exact_payload
                || existing.related_peer != Some(peer)
                || existing.peer_targets != peer_targets
                || existing.expires_at != expires_at
            {
                return Err(Error::Unauthorized);
            }
            tx.commit()?;
            return Ok(existing);
        }
        let mut record = load_match_tx(&tx, owner, peer)?.unwrap_or(MatchRecord::new(owner, peer)?);
        if !record.like(like_id)? {
            return Err(Error::Unauthorized);
        }
        save_match_tx(&tx, &record)?;
        if record.state() == MatchState::Matched
            && let Some(event) =
                insert_notification_tx(&tx, owner, NotificationKind::NewMatch, &record.match_id()?)?
        {
            let _ = event;
        }
        if now >= expires_at {
            return Err(Error::InvalidTime);
        }
        upsert_feedback_tx(&tx, owner, peer, true, now, self.limits.max_bytes)?;
        let operation = insert_operation_tx(
            &tx,
            owner,
            OutgoingOperationKind::Like,
            idempotency_key,
            Some(peer),
            exact_payload,
            peer_targets,
            items,
            expires_at,
            self.limits.max_bytes,
        )?;
        tx.commit()?;
        Ok(operation)
    }

    pub fn create_contact_operation(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        idempotency_key: [u8; 32],
        exact_payload: Vec<u8>,
        peer_targets: Vec<String>,
        expires_at: u64,
    ) -> Result<OperationRecord> {
        let items = [*blake3::hash(&exact_payload).as_bytes()].to_vec();
        validate_operation_inputs(
            idempotency_key,
            &exact_payload,
            &peer_targets,
            &items,
            expires_at,
        )?;
        if owner == peer {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            find_operation_by_key(&tx, owner, OutgoingOperationKind::Contact, idempotency_key)?
        {
            if existing.exact_payload != exact_payload
                || existing.related_peer != Some(peer)
                || existing.peer_targets != peer_targets
                || existing.expires_at != expires_at
            {
                return Err(Error::Unauthorized);
            }
            tx.commit()?;
            return Ok(existing);
        }
        let matched = load_match_tx(&tx, owner, peer)?
            .is_some_and(|record| record.state() == MatchState::Matched);
        if !matched {
            return Err(Error::Unauthorized);
        }
        let operation = insert_operation_tx(
            &tx,
            owner,
            OutgoingOperationKind::Contact,
            idempotency_key,
            Some(peer),
            exact_payload,
            peer_targets,
            items,
            expires_at,
            self.limits.max_bytes,
        )?;
        tx.commit()?;
        Ok(operation)
    }

    pub fn acknowledge_operation_item(
        &mut self,
        owner: ProfileId,
        operation_id: [u8; 16],
        peer_id: &str,
        item: [u8; 32],
        accepted: bool,
    ) -> Result<OperationRecord> {
        validate_peer_key(peer_id)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut operation = load_operation_tx(&tx, owner, operation_id)?.ok_or(Error::NotFound)?;
        if operation.status == OutgoingOperationStatus::Failed
            || !operation
                .peer_targets
                .iter()
                .any(|target| target == peer_id)
            || !operation.items.contains(&item)
        {
            return Err(Error::Unauthorized);
        }
        if operation.status == OutgoingOperationStatus::Completed {
            let confirmed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM operation_item_acks WHERE operation_id=?1 AND peer_id=?2 AND item=?3 AND accepted=1)",
                params![operation_id.as_slice(), peer_id, item.as_slice()],
                |row| row.get(0),
            )?;
            if confirmed {
                tx.commit()?;
                return Ok(operation);
            }
            return Err(Error::Unauthorized);
        }
        tx.execute(
            "INSERT INTO operation_item_acks(operation_id,peer_id,item,accepted) VALUES(?1,?2,?3,?4) ON CONFLICT(operation_id,peer_id,item) DO UPDATE SET accepted=MAX(operation_item_acks.accepted,excluded.accepted)",
            params![operation_id.as_slice(), peer_id, item.as_slice(), accepted],
        )?;
        if accepted {
            tx.execute(
                "DELETE FROM operation_item_failures WHERE operation_id=?1 AND peer_id=?2 AND item=?3",
                params![operation_id.as_slice(), peer_id, item.as_slice()],
            )?;
        }
        let accepted_count: u32 = tx.query_row(
            "SELECT count(*) FROM operation_item_acks WHERE operation_id=?1 AND accepted=1",
            [operation_id.as_slice()],
            |row| row.get(0),
        )?;
        let required = operation.peer_targets.len() * operation.items.len();
        let status = if accepted_count as usize >= required {
            OutgoingOperationStatus::Completed
        } else if accepted_count > 0 {
            OutgoingOperationStatus::Partial
        } else {
            OutgoingOperationStatus::Pending
        };
        tx.execute(
            "UPDATE outgoing_operations SET status=?1 WHERE id=?2 AND owner=?3",
            params![
                operation_status_value(status),
                operation_id.as_slice(),
                owner.0.as_slice()
            ],
        )?;
        operation = load_operation_tx(&tx, owner, operation_id)?.ok_or(Error::NotFound)?;
        tx.commit()?;
        Ok(operation)
    }

    pub fn record_operation_failure(
        &mut self,
        owner: ProfileId,
        operation_id: [u8; 16],
        peer_id: &str,
        item: [u8; 32],
        reason: DeliveryFailureKind,
    ) -> Result<OperationRecord> {
        validate_peer_key(peer_id)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&tx, owner, operation_id)?.ok_or(Error::NotFound)?;
        if operation.status == OutgoingOperationStatus::Failed
            || operation.status == OutgoingOperationStatus::Completed
            || !operation
                .peer_targets
                .iter()
                .any(|target| target == peer_id)
            || !operation.items.contains(&item)
        {
            return Err(Error::Unauthorized);
        }
        let accepted: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_item_acks WHERE operation_id=?1 AND peer_id=?2 AND item=?3 AND accepted=1)",
            params![operation_id.as_slice(), peer_id, item.as_slice()],
            |row| row.get(0),
        )?;
        if accepted {
            tx.commit()?;
            return Ok(operation);
        }
        tx.execute(
            "INSERT INTO operation_item_acks(operation_id,peer_id,item,accepted) VALUES(?1,?2,?3,0) ON CONFLICT(operation_id,peer_id,item) DO NOTHING",
            params![operation_id.as_slice(), peer_id, item.as_slice()],
        )?;
        tx.execute(
            "INSERT INTO operation_item_failures(operation_id,peer_id,item,reason) VALUES(?1,?2,?3,?4) ON CONFLICT(operation_id,peer_id,item) DO UPDATE SET reason=excluded.reason",
            params![operation_id.as_slice(), peer_id, item.as_slice(), delivery_failure_value(reason)],
        )?;
        let operation = load_operation_tx(&tx, owner, operation_id)?.ok_or(Error::NotFound)?;
        tx.commit()?;
        Ok(operation)
    }

    pub fn fail_operation(
        &mut self,
        owner: ProfileId,
        operation_id: [u8; 16],
    ) -> Result<OperationRecord> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&tx, owner, operation_id)?.ok_or(Error::NotFound)?;
        if operation.status == OutgoingOperationStatus::Completed {
            return Err(Error::Unauthorized);
        }
        tx.execute(
            "UPDATE outgoing_operations SET status=3 WHERE owner=?1 AND id=?2 AND status IN (0,1,3)",
            params![owner.0.as_slice(), operation_id.as_slice()],
        )?;
        let failed = load_operation_tx(&tx, owner, operation_id)?.ok_or(Error::NotFound)?;
        tx.commit()?;
        Ok(failed)
    }

    pub fn operation(&self, owner: ProfileId, id: [u8; 16]) -> Result<Option<OperationRecord>> {
        load_operation_tx(&self.connection, owner, id)
    }

    pub fn operation_by_key(
        &self,
        owner: ProfileId,
        kind: OutgoingOperationKind,
        idempotency_key: [u8; 32],
    ) -> Result<Option<OperationRecord>> {
        find_operation_by_key(&self.connection, owner, kind, idempotency_key)
    }

    pub fn pending_operations(
        &self,
        owner: ProfileId,
        limit: usize,
    ) -> Result<Vec<OperationRecord>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT id FROM outgoing_operations WHERE owner=?1 AND status IN (0,1) ORDER BY rowid LIMIT ?2",
        )?;
        let ids = statement.query_map(params![owner.0.as_slice(), limit as u32], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut operations = Vec::new();
        for id in ids {
            let id: [u8; 16] = id?.try_into().map_err(|_| Error::InvalidInput)?;
            operations
                .push(load_operation_tx(&self.connection, owner, id)?.ok_or(Error::NotFound)?);
        }
        Ok(operations)
    }

    /// Reads pending operations in rotating ID order so a bounded drain cannot starve later rows.
    pub fn pending_operations_rotated(
        &mut self,
        owner: ProfileId,
        limit: usize,
    ) -> Result<Vec<OperationRecord>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cursor: Option<Vec<u8>> = tx
            .query_row(
                "SELECT operation_id FROM operation_drain_cursor WHERE owner=?1",
                params![owner.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let mut ids = pending_operation_ids(&tx, owner, cursor.as_deref(), true, limit)?;
        if ids.len() < limit {
            let remaining = limit - ids.len();
            ids.extend(pending_operation_ids(
                &tx,
                owner,
                cursor.as_deref(),
                false,
                remaining,
            )?);
        }
        let mut operations = Vec::with_capacity(ids.len());
        for id in ids {
            operations.push(load_operation_tx(&tx, owner, id)?.ok_or(Error::NotFound)?);
        }
        if let Some(last) = operations.last() {
            tx.execute(
                "INSERT INTO operation_drain_cursor(owner,operation_id) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET operation_id=excluded.operation_id",
                params![owner.0.as_slice(), last.id.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(operations)
    }

    pub fn operations_after(
        &self,
        owner: ProfileId,
        after_id: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<Vec<OperationRecord>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT id FROM outgoing_operations WHERE owner=?1 AND (?2 IS NULL OR id>?2) ORDER BY id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                owner.0.as_slice(),
                after_id.map(|id| id.to_vec()),
                limit as u32
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut operations = Vec::new();
        for row in rows {
            let id: [u8; 16] = row?.try_into().map_err(|_| Error::InvalidInput)?;
            operations
                .push(load_operation_tx(&self.connection, owner, id)?.ok_or(Error::NotFound)?);
        }
        Ok(operations)
    }

    // Publication, local blobs, and the immutable retry record commit as one unit.
    #[allow(clippy::too_many_arguments)]
    pub fn save_publication_bundle(
        &mut self,
        owner: ProfileId,
        profile: &PublicProfile,
        photos: &[(PhotoManifest, ContentLease, Vec<u8>)],
        issuers: &TrustedIssuers,
        now: u64,
        idempotency_key: [u8; 32],
        exact_payload: Vec<u8>,
        peer_targets: Vec<String>,
        items: Vec<[u8; 32]>,
        expires_at: u64,
    ) -> Result<OperationRecord> {
        profile.verify(issuers, now)?;
        if owner != profile.owner || photos.len() > 6 {
            return Err(Error::Unauthorized);
        }
        validate_operation_inputs(
            idempotency_key,
            &exact_payload,
            &peer_targets,
            &items,
            expires_at,
        )?;
        let profile_data = postcard::to_allocvec(profile).map_err(|_| Error::Serialization)?;
        if profile_data.len() > 16 * 1024 {
            return Err(Error::LimitExceeded);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = find_operation_by_key(
            &tx,
            owner,
            OutgoingOperationKind::Publication,
            idempotency_key,
        )? {
            if existing.exact_payload != exact_payload
                || existing.peer_targets != peer_targets
                || existing.items != items
                || existing.expires_at != expires_at
            {
                return Err(Error::Unauthorized);
            }
            tx.commit()?;
            return Ok(existing);
        }
        let old: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT revision,data FROM profiles WHERE id=?1",
                [profile.owner.0.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((revision, old_data)) = old {
            let revision = u64::try_from(revision).map_err(|_| Error::InvalidInput)?;
            if revision > profile.revision {
                return Err(Error::Unauthorized);
            }
            if revision == profile.revision && old_data != profile_data {
                return Err(Error::Unauthorized);
            }
        }
        let expires_sql = sql_u64(profile.expires_at)?;
        let revision_sql = sql_u64(profile.revision)?;
        tx.execute(
            "INSERT INTO profiles(id,data,expires_at,revision) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET data=excluded.data,expires_at=excluded.expires_at,revision=excluded.revision",
            params![profile.owner.0.as_slice(), profile_data, expires_sql, revision_sql],
        )?;
        tx.execute(
            "UPDATE outgoing_operations SET status=3 WHERE owner=?1 AND kind=1 AND status IN (0,1) AND idempotency_key<>?2",
            params![owner.0.as_slice(), idempotency_key.as_slice()],
        )?;
        for (manifest, lease, bytes) in photos {
            lease.verify(&profile.credential, issuers, now)?;
            if !profile.photos.contains(manifest)
                || lease.owner != owner
                || lease.hash != manifest.hash
                || lease.byte_count != manifest.byte_count
                || bytes.len() != manifest.byte_count as usize
                || ContentHash::digest(bytes) != manifest.hash
                || bytes.len() > 4 * 1024 * 1024
                || lease.expires_at > profile.expires_at
            {
                return Err(Error::Unauthorized);
            }
            let existing: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM blobs WHERE hash=?1",
                    [manifest.hash.0.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if existing
                .as_deref()
                .is_some_and(|old| old != bytes.as_slice())
            {
                return Err(Error::InvalidInput);
            }
            let lease_data = postcard::to_allocvec(lease).map_err(|_| Error::Serialization)?;
            if existing.is_none() {
                tx.execute(
                    "INSERT INTO blobs(hash,data) VALUES(?1,?2)",
                    params![manifest.hash.0.as_slice(), bytes],
                )?;
            }
            tx.execute(
                "INSERT INTO photo_leases(owner,hash,expires_at,authorization) VALUES(?1,?2,?3,?4) ON CONFLICT(owner,hash) DO UPDATE SET expires_at=excluded.expires_at,authorization=excluded.authorization",
                params![owner.0.as_slice(), manifest.hash.0.as_slice(), sql_u64(lease.expires_at)?, lease_data],
            )?;
        }
        let operation = insert_operation_tx(
            &tx,
            owner,
            OutgoingOperationKind::Publication,
            idempotency_key,
            None,
            exact_payload,
            peer_targets,
            items,
            expires_at,
            self.limits.max_bytes,
        )?;
        tx.commit()?;
        Ok(operation)
    }

    pub fn list_match_records(&self, owner: ProfileId, limit: usize) -> Result<Vec<MatchRecord>> {
        self.match_records_after(owner, None, limit)
    }

    pub fn match_records_after(
        &self,
        owner: ProfileId,
        after: Option<ProfileId>,
        limit: usize,
    ) -> Result<Vec<MatchRecord>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self
            .connection
            .prepare("SELECT peer FROM match_state WHERE owner=?1 AND (?2 IS NULL OR peer>?2) ORDER BY peer LIMIT ?3")?;
        let peers = statement.query_map(
            params![owner.0.as_slice(), after.map(|id| id.0.to_vec()), 512u32],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut records = Vec::new();
        for peer in peers {
            let peer = ProfileId(peer?.try_into().map_err(|_| Error::InvalidInput)?);
            records.push(load_match_tx(&self.connection, owner, peer)?.ok_or(Error::NotFound)?);
        }
        Ok(records)
    }

    pub fn incoming_like_records(
        &self,
        owner: ProfileId,
        limit: usize,
    ) -> Result<Vec<(MatchRecord, VerifiedCredential)>> {
        self.incoming_like_records_after(owner, None, limit)
    }

    pub fn incoming_like_records_after(
        &self,
        owner: ProfileId,
        after: Option<ProfileId>,
        limit: usize,
    ) -> Result<Vec<(MatchRecord, VerifiedCredential)>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT peer FROM match_state WHERE owner=?1 AND state IN (2,3) AND (?2 IS NULL OR peer>?2) ORDER BY peer LIMIT ?3",
        )?;
        let peers = statement.query_map(
            params![
                owner.0.as_slice(),
                after.map(|id| id.0.to_vec()),
                limit as u32
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut incoming = Vec::new();
        for peer in peers {
            let peer = ProfileId(peer?.try_into().map_err(|_| Error::InvalidInput)?);
            let record = load_match_tx(&self.connection, owner, peer)?.ok_or(Error::NotFound)?;
            let credential =
                load_peer_credential_tx(&self.connection, owner, peer)?.ok_or(Error::NotFound)?;
            incoming.push((record, credential));
        }
        Ok(incoming)
    }

    pub fn incoming_contact_disclosures_for_match(
        &self,
        owner: ProfileId,
        match_id: [u8; 32],
        limit: usize,
    ) -> Result<Vec<ContactDisclosure>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT data FROM incoming_contacts WHERE recipient=?1 ORDER BY rowid LIMIT 1024",
        )?;
        let rows = statement.query_map([owner.0.as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut disclosures = Vec::new();
        for row in rows {
            let disclosure: ContactDisclosure =
                postcard::from_bytes(&row?).map_err(|_| Error::Serialization)?;
            if disclosure.match_id == match_id {
                disclosures.push(disclosure);
                if disclosures.len() == limit {
                    break;
                }
            }
        }
        Ok(disclosures)
    }

    pub fn incoming_contact_disclosures_for_match_page(
        &self,
        owner: ProfileId,
        match_id: [u8; 32],
        after: Option<(ProfileId, [u8; 16])>,
        limit: usize,
    ) -> Result<ContactDisclosurePage> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        const SCAN_LIMIT: usize = 512;
        let mut statement = self.connection.prepare(
            "SELECT sender,id,data FROM incoming_contacts WHERE recipient=?1 AND (?2 IS NULL OR sender>?2 OR (sender=?2 AND id>?3)) ORDER BY sender,id LIMIT ?4",
        )?;
        let after_sender = after.map(|(sender, _)| sender.0.to_vec());
        let after_id = after.map(|(_, id)| id.to_vec());
        let rows = statement.query_map(
            params![
                owner.0.as_slice(),
                after_sender,
                after_id,
                (SCAN_LIMIT + 1) as u32
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let total_rows = rows.len();
        let mut disclosures = Vec::new();
        let mut cursor = None;
        let mut processed = 0;
        for (sender, id, data) in rows.into_iter().take(SCAN_LIMIT) {
            let sender = ProfileId(sender.try_into().map_err(|_| Error::InvalidInput)?);
            let id: [u8; 16] = id.try_into().map_err(|_| Error::InvalidInput)?;
            cursor = Some((sender, id));
            processed += 1;
            let disclosure: ContactDisclosure =
                postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
            if disclosure.match_id == match_id {
                disclosures.push(disclosure);
                if disclosures.len() == limit {
                    break;
                }
            }
        }
        let next_cursor = (processed < total_rows).then_some(cursor).flatten();
        Ok(ContactDisclosurePage {
            disclosures,
            next_cursor,
        })
    }

    pub fn mark_pass(&mut self, owner: ProfileId, peer: ProfileId, now: u64) -> Result<()> {
        if owner == peer {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load_match_tx(&tx, owner, peer)?.unwrap_or(MatchRecord::new(owner, peer)?);
        record.reject()?;
        save_match_tx(&tx, &record)?;
        upsert_feedback_tx(&tx, owner, peer, false, now, self.limits.max_bytes)?;
        tx.execute(
            "UPDATE outgoing_operations SET status=3 WHERE owner=?1 AND related_peer=?2 AND status IN (0,1)",
            params![owner.0.as_slice(), peer.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_feedback(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        liked: bool,
        seen_at: u64,
    ) -> Result<()> {
        if owner == peer {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        upsert_feedback_tx(&tx, owner, peer, liked, seen_at, self.limits.max_bytes)?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically persists the consent FSM transition, deduplicated feedback, and model snapshot.
    /// Returns false when the same intent was already recorded, so callers do not train twice.
    pub fn apply_feedback_and_model(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        liked: bool,
        seen_at: u64,
        snapshot: &[u8],
    ) -> Result<bool> {
        if owner == peer || snapshot.is_empty() || snapshot.len() > 64 * 1024 {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<bool> = tx
            .query_row(
                "SELECT liked FROM trained_feedback WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), peer.0.as_slice()],
                |row| row.get::<_, i64>(0).map(|value| value != 0),
            )
            .optional()?;
        if previous == Some(liked) {
            tx.commit()?;
            return Ok(false);
        }
        if liked {
            let state = load_match_tx(&tx, owner, peer)?.map(|record| record.state());
            if !matches!(state, Some(MatchState::Outgoing | MatchState::Matched)) {
                return Err(Error::Unauthorized);
            }
        } else {
            let record = load_match_tx(&tx, owner, peer)?;
            match record.as_ref().map(MatchRecord::state) {
                Some(MatchState::Blocked) => return Err(Error::Unauthorized),
                Some(MatchState::Rejected) => {}
                _ => {
                    let mut record = record.unwrap_or(MatchRecord::new(owner, peer)?);
                    record.reject()?;
                    save_match_tx(&tx, &record)?;
                    tx.execute(
                        "UPDATE outgoing_operations SET status=3 WHERE owner=?1 AND related_peer=?2 AND status IN (0,1)",
                        params![owner.0.as_slice(), peer.0.as_slice()],
                    )?;
                }
            }
        }
        upsert_feedback_tx(&tx, owner, peer, liked, seen_at, self.limits.max_bytes)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM preference_models WHERE owner=?1)",
            [owner.0.as_slice()],
            |row| row.get(0),
        )?;
        if !exists && storage_bytes(&tx)? + snapshot.len() as u64 + 32 > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO preference_models(owner,data) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET data=excluded.data",
            params![owner.0.as_slice(), snapshot],
        )?;
        tx.execute(
            "INSERT INTO trained_feedback(owner,peer,liked) VALUES(?1,?2,?3) ON CONFLICT(owner,peer) DO UPDATE SET liked=excluded.liked",
            params![owner.0.as_slice(), peer.0.as_slice(), liked],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn reset_local_learning(&mut self, owner: ProfileId) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM preference_models WHERE owner=?1",
            [owner.0.as_slice()],
        )?;
        tx.execute(
            "DELETE FROM local_feedback WHERE owner=?1",
            [owner.0.as_slice()],
        )?;
        tx.execute(
            "DELETE FROM trained_feedback WHERE owner=?1",
            [owner.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn cache_candidate(
        &mut self,
        owner: ProfileId,
        profile: &PublicProfile,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<()> {
        profile.verify(issuers, now)?;
        if profile.owner == owner {
            return Err(Error::InvalidInput);
        }
        let data = postcard::to_allocvec(profile).map_err(|_| Error::Serialization)?;
        if data.len() > 16 * 1024 {
            return Err(Error::LimitExceeded);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old_data: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM candidate_cache WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), profile.owner.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old_bytes) = &old_data {
            let old: PublicProfile =
                postcard::from_bytes(old_bytes).map_err(|_| Error::Serialization)?;
            if old.revision > profile.revision
                || (old.revision == profile.revision && old_bytes.as_slice() != data.as_slice())
            {
                return Err(Error::Unauthorized);
            }
        }
        save_peer_credential_tx(&tx, owner, &profile.credential, self.limits.max_bytes)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM candidate_cache WHERE owner=?1 AND peer=?2)",
            params![owner.0.as_slice(), profile.owner.0.as_slice()],
            |row| row.get(0),
        )?;
        let count: u32 = tx.query_row(
            "SELECT count(*) FROM candidate_cache WHERE owner=?1",
            [owner.0.as_slice()],
            |row| row.get(0),
        )?;
        if !exists && count >= 512 {
            return Err(Error::LimitExceeded);
        }
        if !exists && storage_bytes(&tx)? + data.len() as u64 + 64 > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO candidate_cache(owner,peer,data,cached_at) VALUES(?1,?2,?3,?4) ON CONFLICT(owner,peer) DO UPDATE SET data=excluded.data,cached_at=excluded.cached_at",
            params![owner.0.as_slice(), profile.owner.0.as_slice(), data, sql_u64(now)?],
        )?;
        if old_data
            .as_deref()
            .is_some_and(|old| old != data.as_slice())
        {
            tx.execute(
                "DELETE FROM candidate_embeddings WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), profile.owner.0.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn candidate_profiles(
        &self,
        owner: ProfileId,
        issuers: &TrustedIssuers,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PublicProfile>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self
            .connection
            .prepare("SELECT data FROM candidate_cache WHERE owner=?1 ORDER BY peer LIMIT ?2")?;
        let rows = statement.query_map(params![owner.0.as_slice(), limit as u32], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut profiles = Vec::new();
        for row in rows {
            let profile: PublicProfile =
                postcard::from_bytes(&row?).map_err(|_| Error::Serialization)?;
            if profile.verify(issuers, now).is_ok() {
                profiles.push(profile);
                if profiles.len() == limit {
                    break;
                }
            }
        }
        Ok(profiles)
    }

    pub fn candidate_profile(
        &self,
        owner: ProfileId,
        peer: ProfileId,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Option<PublicProfile>> {
        let data: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT data FROM candidate_cache WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), peer.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(data) = data else {
            return Ok(None);
        };
        let profile: PublicProfile =
            postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
        if profile.verify(issuers, now).is_ok() {
            Ok(Some(profile))
        } else {
            Ok(None)
        }
    }

    pub fn candidate_profiles_after(
        &self,
        owner: ProfileId,
        issuers: &TrustedIssuers,
        now: u64,
        after: Option<ProfileId>,
        limit: usize,
    ) -> Result<Vec<PublicProfile>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT data FROM candidate_cache WHERE owner=?1 AND (?2 IS NULL OR peer>?2) ORDER BY peer LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                owner.0.as_slice(),
                after.map(|id| id.0.to_vec()),
                limit as u32
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut profiles = Vec::new();
        for row in rows {
            let profile: PublicProfile =
                postcard::from_bytes(&row?).map_err(|_| Error::Serialization)?;
            if profile.verify(issuers, now).is_ok() {
                profiles.push(profile);
            }
        }
        Ok(profiles)
    }

    pub fn save_candidate_embedding(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        source_hash: [u8; 32],
        version: u16,
        values: &[f64],
    ) -> Result<()> {
        if owner == peer
            || source_hash == [0; 32]
            || values.is_empty()
            || values.len() > 4096
            || values
                .iter()
                .any(|value| !value.is_finite() || value.abs() > 1.0)
        {
            return Err(Error::InvalidInput);
        }
        let data = postcard::to_allocvec(values).map_err(|_| Error::Serialization)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let cached: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM candidate_cache WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), peer.0.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(cached) = cached else {
            return Err(Error::NotFound);
        };
        let profile: PublicProfile =
            postcard::from_bytes(&cached).map_err(|_| Error::Serialization)?;
        if !profile
            .photos
            .iter()
            .any(|photo| photo.hash.0 == source_hash)
        {
            return Err(Error::Unauthorized);
        }
        if storage_bytes(&tx)? + data.len() as u64 + 96 > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO candidate_embeddings(owner,peer,source_hash,version,data) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(owner,peer) DO UPDATE SET source_hash=excluded.source_hash,version=excluded.version,data=excluded.data",
            params![owner.0.as_slice(), peer.0.as_slice(), source_hash.as_slice(), version, data],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn candidate_embedding(
        &self,
        owner: ProfileId,
        peer: ProfileId,
        source_hash: [u8; 32],
    ) -> Result<Option<(u16, Vec<f64>)>> {
        let row: Option<(u16, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT version,data FROM candidate_embeddings WHERE owner=?1 AND peer=?2 AND source_hash=?3",
                params![owner.0.as_slice(), peer.0.as_slice(), source_hash.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(version, data)| {
            let values: Vec<f64> = postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
            if values.is_empty()
                || values.len() > 4096
                || values
                    .iter()
                    .any(|value| !value.is_finite() || value.abs() > 1.0)
            {
                return Err(Error::InvalidInput);
            }
            Ok((version, values))
        })
        .transpose()
    }

    pub fn candidate_embedding_any(
        &self,
        owner: ProfileId,
        peer: ProfileId,
    ) -> Result<Option<CandidateEmbedding>> {
        let row: Option<(Vec<u8>, u16, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT source_hash,version,data FROM candidate_embeddings WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), peer.0.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(hash, version, data)| {
            let source_hash = hash.try_into().map_err(|_| Error::InvalidInput)?;
            let values: Vec<f64> = postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
            if values.is_empty()
                || values.len() > 4096
                || values
                    .iter()
                    .any(|value| !value.is_finite() || value.abs() > 1.0)
            {
                return Err(Error::InvalidInput);
            }
            Ok((source_hash, version, values))
        })
        .transpose()
    }

    pub fn seen_profiles(&self, owner: ProfileId, limit: usize) -> Result<Vec<ProfileId>> {
        if limit == 0 || limit > 512 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT peer FROM local_feedback WHERE owner=?1 ORDER BY seen_at DESC,peer LIMIT ?2",
        )?;
        let rows = statement.query_map(params![owner.0.as_slice(), limit as u32], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| Ok(ProfileId(row?.try_into().map_err(|_| Error::InvalidInput)?)))
            .collect()
    }

    pub fn save_preference_model(&mut self, owner: ProfileId, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > 64 * 1024 {
            return Err(Error::LimitExceeded);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM preference_models WHERE owner=?1)",
            [owner.0.as_slice()],
            |row| row.get(0),
        )?;
        if !exists && storage_bytes(&tx)? + data.len() as u64 + 32 > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO preference_models(owner,data) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET data=excluded.data",
            params![owner.0.as_slice(), data],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn load_preference_model(&self, owner: ProfileId) -> Result<Option<Vec<u8>>> {
        self.connection
            .query_row(
                "SELECT data FROM preference_models WHERE owner=?1",
                [owner.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::from)
    }

    pub fn save_local_report(
        &mut self,
        owner: ProfileId,
        report_id: [u8; 16],
        data: &[u8],
        created_at: u64,
    ) -> Result<()> {
        if report_id == [0; 16] || data.is_empty() || data.len() > 2048 || created_at == 0 {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM local_reports WHERE owner=?1 AND report_id=?2)",
            params![owner.0.as_slice(), report_id.as_slice()],
            |row| row.get(0),
        )?;
        if exists {
            let prior: Vec<u8> = tx.query_row(
                "SELECT data FROM local_reports WHERE owner=?1 AND report_id=?2",
                params![owner.0.as_slice(), report_id.as_slice()],
                |row| row.get(0),
            )?;
            if prior != data {
                return Err(Error::Unauthorized);
            }
            tx.commit()?;
            return Ok(());
        }
        let count: u32 = tx.query_row(
            "SELECT count(*) FROM local_reports WHERE owner=?1",
            [owner.0.as_slice()],
            |row| row.get(0),
        )?;
        if count >= 256 || storage_bytes(&tx)? + data.len() as u64 + 64 > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO local_reports(owner,report_id,data,created_at) VALUES(?1,?2,?3,?4)",
            params![
                owner.0.as_slice(),
                report_id.as_slice(),
                data,
                sql_u64(created_at)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn local_reports(&self, owner: ProfileId, limit: usize) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .local_reports_after(owner, None, limit)?
            .into_iter()
            .map(|report| report.data)
            .collect())
    }

    pub fn local_reports_after(
        &self,
        owner: ProfileId,
        after: Option<(u64, [u8; 16])>,
        limit: usize,
    ) -> Result<Vec<LocalReportRecord>> {
        if limit == 0 || limit > 65 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT report_id,created_at,data FROM local_reports WHERE owner=?1 AND (?2 IS NULL OR created_at<?2 OR (created_at=?2 AND report_id>?3)) ORDER BY created_at DESC,report_id LIMIT ?4",
        )?;
        let after_created = after.map(|(created, _)| sql_u64(created)).transpose()?;
        let after_id = after.map(|(_, id)| id.to_vec());
        let rows = statement.query_map(
            params![owner.0.as_slice(), after_created, after_id, limit as u32],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (report_id, created_at, data) = row?;
            Ok(LocalReportRecord {
                report_id: report_id.try_into().map_err(|_| Error::InvalidInput)?,
                created_at: u64::try_from(created_at).map_err(|_| Error::InvalidInput)?,
                data,
            })
        })
        .collect()
    }

    pub fn list_profiles(
        &self,
        issuers: &TrustedIssuers,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PublicProfile>> {
        let now_sql = sql_u64(now)?;
        if limit == 0 || limit > 50 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self
            .connection
            .prepare("SELECT data FROM profiles WHERE expires_at>?1 ORDER BY id LIMIT ?2")?;
        let values =
            statement.query_map(params![now_sql, limit as u32], |r| r.get::<_, Vec<u8>>(0))?;
        let mut profiles = Vec::new();
        for value in values {
            let data = value?;
            let profile: PublicProfile =
                postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
            profile.verify(issuers, now)?;
            profiles.push(profile);
        }
        Ok(profiles)
    }

    pub fn store_photo(
        &mut self,
        manifest_hash: ContentHash,
        lease: &ContentLease,
        blob: &[u8],
        owner: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<()> {
        lease.verify(owner, issuers, now)?;
        let now_sql = sql_u64(now)?;
        let lease_expiry = sql_u64(lease.expires_at)?;
        if lease.hash != manifest_hash
            || lease.byte_count as usize != blob.len()
            || ContentHash::digest(blob) != manifest_hash
            || blob.len() > 4 * 1024 * 1024
        {
            return Err(Error::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let profile_data: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM profiles WHERE id=?1 AND expires_at>?2",
                params![lease.owner.0.as_slice(), now_sql],
                |row| row.get(0),
            )
            .optional()?;
        let profile_data = profile_data.ok_or(Error::Unauthorized)?;
        let profile: PublicProfile =
            postcard::from_bytes(&profile_data).map_err(|_| Error::Serialization)?;
        profile.verify(issuers, now)?;
        if !profile
            .photos
            .iter()
            .any(|photo| photo.hash == manifest_hash && photo.byte_count == lease.byte_count)
            || lease.expires_at > profile.expires_at
        {
            return Err(Error::Unauthorized);
        }
        let already: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM blobs WHERE hash=?1",
                [manifest_hash.0.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let blob_is_new = already.is_none();
        if let Some(bytes) = already
            && bytes.as_slice() != blob
        {
            return Err(Error::InvalidInput);
        }
        let lease_bytes = postcard::to_allocvec(lease).map_err(|_| Error::Serialization)?;
        let lease_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM photo_leases WHERE owner=?1 AND hash=?2)",
            params![lease.owner.0.as_slice(), manifest_hash.0.as_slice()],
            |row| row.get(0),
        )?;
        let additional_bytes = if blob_is_new {
            blob.len() as u64 + 32
        } else {
            0
        } + if lease_exists {
            0
        } else {
            lease_bytes.len() as u64 + 72
        };
        if storage_bytes(&tx)? + additional_bytes > self.limits.max_bytes {
            return Err(Error::LimitExceeded);
        }
        if blob_is_new {
            tx.execute(
                "INSERT INTO blobs(hash,data) VALUES(?1,?2)",
                params![manifest_hash.0.as_slice(), blob],
            )?;
        }
        tx.execute("INSERT OR IGNORE INTO photo_leases(owner,hash,expires_at,authorization) VALUES(?1,?2,?3,?4)", params![lease.owner.0.as_slice(), manifest_hash.0.as_slice(), lease_expiry, lease_bytes])?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_photo(
        &self,
        owner: ProfileId,
        hash: ContentHash,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Option<Vec<u8>>> {
        let now_sql = sql_u64(now)?;
        let profile_data: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT data FROM profiles WHERE id=?1 AND expires_at>?2",
                params![owner.0.as_slice(), now_sql],
                |row| row.get(0),
            )
            .optional()?;
        let Some(profile_data) = profile_data else {
            return Ok(None);
        };
        let profile: PublicProfile =
            postcard::from_bytes(&profile_data).map_err(|_| Error::Serialization)?;
        profile.verify(issuers, now)?;
        if !profile.photos.iter().any(|photo| photo.hash == hash) {
            return Ok(None);
        }
        let bytes: Option<Vec<u8>> = self.connection.query_row("SELECT b.data FROM blobs b JOIN photo_leases l ON l.hash=b.hash WHERE l.owner=?1 AND l.hash=?2 AND l.expires_at>?3", params![owner.0.as_slice(), hash.0.as_slice(), now_sql], |r| r.get(0)).optional()?;
        if let Some(ref data) = bytes
            && ContentHash::digest(data) != hash
        {
            return Err(Error::InvalidInput);
        }
        Ok(bytes)
    }

    pub fn deposit_mailbox(&mut self, parcel: &MailboxParcel, now: u64) -> Result<bool> {
        parcel.verify_header(now)?;
        let now_sql = sql_u64(now)?;
        let expires_at = sql_u64(parcel.expires_at)?;
        let data = postcard::to_allocvec(parcel).map_err(|_| Error::Serialization)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM mailbox WHERE expires_at<=?1", [now_sql])?;
        tx.execute("DELETE FROM seen_messages WHERE expires_at<=?1", [now_sql])?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM seen_messages WHERE id=?1 AND recipient=?2)",
            params![parcel.id.as_slice(), parcel.recipient.0.as_slice()],
            |r| r.get(0),
        )?;
        if exists {
            return Ok(false);
        }
        let count: u32 = tx.query_row("SELECT count(*) FROM mailbox", [], |r| r.get(0))?;
        let recipient_count: u32 = tx.query_row(
            "SELECT count(*) FROM mailbox WHERE recipient=?1",
            [parcel.recipient.0.as_slice()],
            |r| r.get(0),
        )?;
        if count >= self.limits.max_mailbox_messages
            || recipient_count >= self.limits.max_messages_per_recipient
            || storage_bytes(&tx)? + data.len() as u64 + 112 > self.limits.max_bytes
        {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO mailbox(id,recipient,expires_at,data) VALUES(?1,?2,?3,?4)",
            params![
                parcel.id.as_slice(),
                parcel.recipient.0.as_slice(),
                expires_at,
                data
            ],
        )?;
        tx.execute(
            "INSERT INTO seen_messages(id,recipient,expires_at) VALUES(?1,?2,?3)",
            params![
                parcel.id.as_slice(),
                parcel.recipient.0.as_slice(),
                expires_at
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn poll_mailbox(
        &self,
        recipient: &VerifiedCredential,
        issuers: &TrustedIssuers,
        challenge: &[u8; 32],
        proof: &[u8],
        now: u64,
        limit: usize,
    ) -> Result<Vec<MailboxParcel>> {
        self.poll_mailbox_at(recipient, issuers, challenge, proof, now, now, limit)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn poll_mailbox_at(
        &self,
        recipient: &VerifiedCredential,
        issuers: &TrustedIssuers,
        challenge: &[u8; 32],
        proof: &[u8],
        proof_time: u64,
        now: u64,
        limit: usize,
    ) -> Result<Vec<MailboxParcel>> {
        recipient.verify(issuers, now)?;
        let now_sql = sql_u64(now)?;
        if limit == 0 || limit > 256 {
            return Err(Error::LimitExceeded);
        }
        if proof_time.abs_diff(now) > 30 {
            return Err(Error::InvalidTime);
        }
        let claims = PollClaims {
            recipient: recipient.profile_id(),
            challenge: *challenge,
            now: proof_time,
        };
        verify_signature(
            &recipient.claims.signing_key,
            POLL_DOMAIN,
            &canonical(POLL_DOMAIN, &claims)?,
            proof,
        )?;
        let mut statement = self.connection.prepare("SELECT data FROM mailbox WHERE recipient=?1 AND expires_at>?2 ORDER BY expires_at,id LIMIT ?3")?;
        let values = statement.query_map(
            params![recipient.profile_id().0.as_slice(), now_sql, limit as u32],
            |r| r.get::<_, Vec<u8>>(0),
        )?;
        let mut out = Vec::new();
        for value in values {
            let data = value?;
            let parcel: MailboxParcel =
                postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
            parcel.verify_header(now)?;
            if parcel.recipient != recipient.profile_id() {
                return Err(Error::Unauthorized);
            }
            out.push(parcel);
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn poll_mailbox_page(
        &self,
        recipient: &VerifiedCredential,
        issuers: &TrustedIssuers,
        challenge: &[u8; 32],
        proof: &[u8],
        proof_time: u64,
        now: u64,
        cursor: Option<MailboxCursor>,
        limit: usize,
    ) -> Result<MailboxPage> {
        recipient.verify(issuers, now)?;
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        if proof_time.abs_diff(now) > 30 {
            return Err(Error::InvalidTime);
        }
        let claims = PollClaims {
            recipient: recipient.profile_id(),
            challenge: *challenge,
            now: proof_time,
        };
        verify_signature(
            &recipient.claims.signing_key,
            POLL_DOMAIN,
            &canonical(POLL_DOMAIN, &claims)?,
            proof,
        )?;
        let now_sql = sql_u64(now)?;
        let values = match cursor {
            Some(cursor) => {
                let expires = sql_u64(cursor.expires_at)?;
                let mut statement = self.connection.prepare(
                    "SELECT expires_at,id,data FROM mailbox WHERE recipient=?1 AND expires_at>?2 AND (expires_at,id)>(?3,?4) ORDER BY expires_at,id LIMIT ?5",
                )?;
                let rows = statement.query_map(
                    params![
                        recipient.profile_id().0.as_slice(),
                        now_sql,
                        expires,
                        cursor.parcel_id.as_slice(),
                        limit as u32
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            }
            None => {
                let mut statement = self.connection.prepare(
                    "SELECT expires_at,id,data FROM mailbox WHERE recipient=?1 AND expires_at>?2 ORDER BY expires_at,id LIMIT ?3",
                )?;
                let rows = statement.query_map(
                    params![recipient.profile_id().0.as_slice(), now_sql, limit as u32],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            }
        };
        let mut parcels = Vec::with_capacity(values.len());
        let mut next_cursor = None;
        for (expires_at, id, data) in values {
            let parcel: MailboxParcel =
                postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
            parcel.verify_header(now)?;
            if parcel.recipient != recipient.profile_id() || id.as_slice() != parcel.id {
                return Err(Error::Unauthorized);
            }
            next_cursor = Some(MailboxCursor {
                expires_at: u64::try_from(expires_at).map_err(|_| Error::InvalidInput)?,
                parcel_id: parcel.id,
            });
            parcels.push(parcel);
        }
        let completed = parcels.len() < limit;
        Ok(MailboxPage {
            parcels,
            next_cursor,
            completed,
        })
    }

    pub fn load_mailbox_checkpoint(
        &self,
        owner: ProfileId,
        peer: &str,
    ) -> Result<Option<MailboxCursor>> {
        validate_peer_key(peer)?;
        let row: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT expires_at,parcel_id FROM sync_checkpoints WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), peer],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(expires_at, parcel_id)| {
            let parcel_id: [u8; 16] = parcel_id.try_into().map_err(|_| Error::InvalidInput)?;
            Ok(MailboxCursor {
                expires_at: u64::try_from(expires_at).map_err(|_| Error::InvalidInput)?,
                parcel_id,
            })
        })
        .transpose()
    }

    /// `None` clears progress after a completed scan so earlier insertions are revisited.
    pub fn save_mailbox_checkpoint(
        &mut self,
        owner: ProfileId,
        peer: &str,
        cursor: Option<MailboxCursor>,
    ) -> Result<()> {
        validate_peer_key(peer)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match cursor {
            Some(cursor) => {
                tx.execute(
                    "INSERT INTO sync_checkpoints(owner,peer,expires_at,parcel_id) VALUES(?1,?2,?3,?4) ON CONFLICT(owner,peer) DO UPDATE SET expires_at=excluded.expires_at,parcel_id=excluded.parcel_id",
                    params![owner.0.as_slice(), peer, sql_u64(cursor.expires_at)?, cursor.parcel_id.as_slice()],
                )?;
            }
            None => {
                tx.execute(
                    "DELETE FROM sync_checkpoints WHERE owner=?1 AND peer=?2",
                    params![owner.0.as_slice(), peer],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn advance_mailbox_checkpoint(
        &mut self,
        owner: ProfileId,
        peer: &str,
        cursor: MailboxCursor,
    ) -> Result<()> {
        self.save_mailbox_checkpoint(owner, peer, Some(cursor))
    }

    /// Records malformed/unsupported item progress without mutating domain state.
    pub fn mark_mailbox_rejected(
        &mut self,
        owner: ProfileId,
        peer: &str,
        cursor: MailboxCursor,
    ) -> Result<()> {
        validate_peer_key(peer)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_rejections WHERE owner=?1 AND peer=?2 AND expires_at=?3 AND parcel_id=?4)",
            params![owner.0.as_slice(), peer, sql_u64(cursor.expires_at)?, cursor.parcel_id.as_slice()],
            |row| row.get(0),
        )?;
        if !exists {
            let count: u32 = tx.query_row(
                "SELECT count(*) FROM sync_rejections WHERE owner=?1",
                [owner.0.as_slice()],
                |row| row.get(0),
            )?;
            if count >= MAX_SYNC_REJECTIONS_PER_OWNER {
                return Err(Error::LimitExceeded);
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO sync_rejections(owner,peer,expires_at,parcel_id) VALUES(?1,?2,?3,?4)",
            params![owner.0.as_slice(), peer, sql_u64(cursor.expires_at)?, cursor.parcel_id.as_slice()],
        )?;
        save_checkpoint_tx(&tx, owner, peer, Some(cursor))?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_notification_preferences(
        &mut self,
        owner: ProfileId,
        preferences: NotificationPreferences,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO notification_preferences(owner,likes_enabled,matches_enabled) VALUES(?1,?2,?3) ON CONFLICT(owner) DO UPDATE SET likes_enabled=excluded.likes_enabled,matches_enabled=excluded.matches_enabled",
            params![owner.0.as_slice(), preferences.likes_enabled, preferences.matches_enabled],
        )?;
        Ok(())
    }

    pub fn notification_preferences(&self, owner: ProfileId) -> Result<NotificationPreferences> {
        load_notification_preferences(&self.connection, owner)
    }

    pub fn pending_notifications(
        &self,
        owner: ProfileId,
        limit: usize,
    ) -> Result<Vec<NotificationEvent>> {
        if limit == 0 || limit > 64 {
            return Err(Error::LimitExceeded);
        }
        let preferences = load_notification_preferences(&self.connection, owner)?;
        let mut statement = self.connection.prepare(
            "SELECT event_id,kind FROM notification_outbox WHERE owner=?1 AND acknowledged=0 AND ((kind=1 AND ?2=1) OR (kind=2 AND ?3=1)) ORDER BY rowid LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                owner.0.as_slice(),
                preferences.likes_enabled,
                preferences.matches_enabled,
                limit as u32
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut events = Vec::new();
        for row in rows {
            let (id, kind) = row?;
            events.push(NotificationEvent {
                event_id: id.try_into().map_err(|_| Error::InvalidInput)?,
                kind: notification_kind(kind)?,
            });
        }
        Ok(events)
    }

    /// Returns true only when this call changes the durable state from Pending to Acknowledged.
    pub fn acknowledge_notification(
        &mut self,
        owner: ProfileId,
        event_id: [u8; 32],
    ) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE notification_outbox SET acknowledged=1 WHERE owner=?1 AND event_id=?2 AND acknowledged=0",
            params![owner.0.as_slice(), event_id.as_slice()],
        )?;
        Ok(changed == 1)
    }

    pub fn signed_poll_proof(
        device: &crate::identity::DeviceKeyPair,
        recipient: ProfileId,
        challenge: [u8; 32],
        now: u64,
    ) -> Result<Vec<u8>> {
        if device.profile_id() != recipient {
            return Err(Error::Unauthorized);
        }
        let bytes = canonical(
            POLL_DOMAIN,
            &PollClaims {
                recipient,
                challenge,
                now,
            },
        )?;
        Ok(device.sign(POLL_DOMAIN, &bytes))
    }

    pub fn load_match(&self, owner: ProfileId, peer: ProfileId) -> Result<Option<MatchRecord>> {
        load_match_tx(&self.connection, owner, peer)
    }

    pub fn apply_local_like(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        id: [u8; 16],
    ) -> Result<MatchRecord> {
        self.apply_local_like_with_events(owner, peer, id)
            .map(|(record, _)| record)
    }

    pub fn apply_local_like_with_events(
        &mut self,
        owner: ProfileId,
        peer: ProfileId,
        id: [u8; 16],
    ) -> Result<(MatchRecord, Vec<NotificationEvent>)> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load_match_tx(&tx, owner, peer)?.unwrap_or(MatchRecord::new(owner, peer)?);
        let changed = record.like(id)?;
        save_match_tx(&tx, &record)?;
        let mut events = Vec::new();
        if changed
            && record.state() == MatchState::Matched
            && let Some(event) =
                insert_notification_tx(&tx, owner, NotificationKind::NewMatch, &record.match_id()?)?
        {
            events.push(event);
        }
        tx.commit()?;
        Ok((record, events))
    }

    pub fn receive_like(
        &mut self,
        envelope: &MessageEnvelope,
        sender_credential: &VerifiedCredential,
        recipient_device: &DeviceKeyPair,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<MatchRecord> {
        self.receive_like_inner(
            envelope,
            sender_credential,
            recipient_device,
            recipient_credential,
            issuers,
            now,
            None,
        )
        .map(|(record, _)| record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_like_checkpointed(
        &mut self,
        envelope: &MessageEnvelope,
        sender_credential: &VerifiedCredential,
        recipient_device: &DeviceKeyPair,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
        peer: &str,
        cursor: MailboxCursor,
    ) -> Result<(MatchRecord, Vec<NotificationEvent>)> {
        validate_peer_key(peer)?;
        self.receive_like_inner(
            envelope,
            sender_credential,
            recipient_device,
            recipient_credential,
            issuers,
            now,
            Some((peer, cursor)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_contact_checkpointed(
        &mut self,
        envelope: &MessageEnvelope,
        sender_credential: &VerifiedCredential,
        recipient_device: &DeviceKeyPair,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
        peer: &str,
        cursor: MailboxCursor,
    ) -> Result<bool> {
        validate_peer_key(peer)?;
        envelope.verify(sender_credential, issuers, now)?;
        if envelope.kind != MessageKind::ContactDisclosure
            || envelope.recipient != recipient_credential.profile_id()
            || recipient_device.profile_id() != recipient_credential.profile_id()
        {
            return Err(Error::Unauthorized);
        }
        let plaintext = envelope.open(
            recipient_device,
            sender_credential,
            recipient_credential,
            issuers,
            now,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        save_peer_credential_tx(
            &tx,
            envelope.recipient,
            sender_credential,
            self.limits.max_bytes,
        )?;
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM processed_contacts WHERE recipient=?1 AND sender=?2 AND id=?3)",
            params![envelope.recipient.0.as_slice(), envelope.sender.0.as_slice(), envelope.id.as_slice()],
            |row| row.get(0),
        )?;
        if duplicate {
            save_checkpoint_tx(&tx, envelope.recipient, peer, Some(cursor))?;
            tx.commit()?;
            return Ok(false);
        }
        let record =
            load_match_tx(&tx, envelope.recipient, envelope.sender)?.ok_or(Error::Unauthorized)?;
        if record.state() != MatchState::Matched {
            return Err(Error::Unauthorized);
        }
        let disclosure = ContactDisclosure::decode(
            &plaintext,
            envelope.sender,
            envelope.recipient,
            record.match_id()?,
        )?;
        let data = postcard::to_allocvec(&disclosure).map_err(|_| Error::Serialization)?;
        let count: u32 = tx.query_row(
            "SELECT count(*) FROM incoming_contacts WHERE recipient=?1",
            [envelope.recipient.0.as_slice()],
            |row| row.get(0),
        )?;
        if count >= 1024 {
            return Err(Error::LimitExceeded);
        }
        tx.execute(
            "INSERT INTO incoming_contacts(recipient,sender,id,data) VALUES(?1,?2,?3,?4)",
            params![
                envelope.recipient.0.as_slice(),
                envelope.sender.0.as_slice(),
                envelope.id.as_slice(),
                data
            ],
        )?;
        tx.execute(
            "INSERT INTO processed_contacts(recipient,sender,id) VALUES(?1,?2,?3)",
            params![
                envelope.recipient.0.as_slice(),
                envelope.sender.0.as_slice(),
                envelope.id.as_slice()
            ],
        )?;
        save_checkpoint_tx(&tx, envelope.recipient, peer, Some(cursor))?;
        tx.commit()?;
        Ok(true)
    }

    pub fn incoming_contact_disclosures(
        &self,
        owner: ProfileId,
        limit: usize,
    ) -> Result<Vec<ContactDisclosure>> {
        if limit == 0 || limit > 100 {
            return Err(Error::LimitExceeded);
        }
        let mut statement = self.connection.prepare(
            "SELECT data FROM incoming_contacts WHERE recipient=?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement.query_map(params![owner.0.as_slice(), limit as u32], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut disclosures = Vec::new();
        for row in rows {
            disclosures.push(postcard::from_bytes(&row?).map_err(|_| Error::Serialization)?);
        }
        Ok(disclosures)
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_like_inner(
        &mut self,
        envelope: &MessageEnvelope,
        sender_credential: &VerifiedCredential,
        recipient_device: &DeviceKeyPair,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
        checkpoint: Option<(&str, MailboxCursor)>,
    ) -> Result<(MatchRecord, Vec<NotificationEvent>)> {
        envelope.verify(sender_credential, issuers, now)?;
        if envelope.recipient != recipient_credential.profile_id()
            || recipient_device.profile_id() != recipient_credential.profile_id()
        {
            return Err(Error::Unauthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        save_peer_credential_tx(
            &tx,
            envelope.recipient,
            sender_credential,
            self.limits.max_bytes,
        )?;
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM processed_likes WHERE recipient=?1 AND sender=?2 AND id=?3)",
            params![envelope.recipient.0.as_slice(), envelope.sender.0.as_slice(), envelope.id.as_slice()],
            |row| row.get(0),
        )?;
        if duplicate {
            let record =
                load_match_tx(&tx, envelope.recipient, envelope.sender)?.ok_or(Error::NotFound)?;
            if let Some((peer, cursor)) = checkpoint {
                save_checkpoint_tx(&tx, envelope.recipient, peer, Some(cursor))?;
            }
            tx.commit()?;
            return Ok((record, Vec::new()));
        }
        let mut candidate = load_match_tx(&tx, envelope.recipient, envelope.sender)?
            .unwrap_or(MatchRecord::new(envelope.recipient, envelope.sender)?);
        let accepted = candidate.receive_envelope(
            envelope,
            sender_credential,
            recipient_device,
            recipient_credential,
            issuers,
            now,
        )?;
        tx.execute(
            "INSERT INTO processed_likes(recipient,sender,id) VALUES(?1,?2,?3)",
            params![
                envelope.recipient.0.as_slice(),
                envelope.sender.0.as_slice(),
                envelope.id.as_slice()
            ],
        )?;
        save_match_tx(&tx, &candidate)?;
        let mut events = Vec::new();
        if accepted {
            if let Some(event) = insert_notification_tx(
                &tx,
                envelope.recipient,
                NotificationKind::NewLike,
                &like_evidence(envelope.sender, envelope.id),
            )? {
                events.push(event);
            }
            if candidate.state() == MatchState::Matched
                && let Some(event) = insert_notification_tx(
                    &tx,
                    envelope.recipient,
                    NotificationKind::NewMatch,
                    &candidate.match_id()?,
                )?
            {
                events.push(event);
            }
        }
        if let Some((peer, cursor)) = checkpoint {
            save_checkpoint_tx(&tx, envelope.recipient, peer, Some(cursor))?;
        }
        tx.commit()?;
        Ok((candidate, events))
    }

    pub fn reject_match(&mut self, owner: ProfileId, peer: ProfileId) -> Result<()> {
        self.set_terminal_match(owner, peer, false)
    }

    pub fn block_match(&mut self, owner: ProfileId, peer: ProfileId) -> Result<()> {
        self.set_terminal_match(owner, peer, true)
    }

    fn set_terminal_match(&mut self, owner: ProfileId, peer: ProfileId, block: bool) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load_match_tx(&tx, owner, peer)?.unwrap_or(MatchRecord::new(owner, peer)?);
        if block {
            record.block();
        } else {
            record.reject()?;
        }
        save_match_tx(&tx, &record)?;
        tx.execute(
            "UPDATE outgoing_operations SET status=3 WHERE owner=?1 AND related_peer=?2 AND kind IN (2,3) AND status IN (0,1)",
            params![owner.0.as_slice(), peer.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn expire(&mut self, now: u64) -> Result<()> {
        let now = sql_u64(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM mailbox WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM seen_messages WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM sync_rejections WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM photo_leases WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM profiles WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM blobs WHERE NOT EXISTS(SELECT 1 FROM photo_leases WHERE photo_leases.hash=blobs.hash)", [])?;
        tx.commit()?;
        Ok(())
    }
}

fn validate_peer_key(peer: &str) -> Result<()> {
    if peer.is_empty()
        || peer.len() > MAX_CHECKPOINT_PEER_ID_BYTES
        || peer.chars().any(char::is_control)
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn save_credential_tx(
    connection: &Connection,
    owner: ProfileId,
    credential: &VerifiedCredential,
    max_bytes: u64,
) -> Result<()> {
    if credential.profile_id() != owner {
        return Err(Error::Unauthorized);
    }
    let data = postcard::to_allocvec(credential).map_err(|_| Error::Serialization)?;
    if data.len() > 16 * 1024 {
        return Err(Error::LimitExceeded);
    }
    let existing = load_credential_tx(connection, owner)?;
    if let Some(previous) = existing
        && (previous.claims.signing_key != credential.claims.signing_key
            || previous.claims.encryption_key != credential.claims.encryption_key
            || credential.claims.issued_at < previous.claims.issued_at)
    {
        return Err(Error::Unauthorized);
    }
    if storage_bytes(connection)?.saturating_add(data.len() as u64 + 32) > max_bytes {
        return Err(Error::LimitExceeded);
    }
    connection.execute(
        "INSERT INTO app_credentials(owner,data) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET data=excluded.data",
        params![owner.0.as_slice(), data],
    )?;
    Ok(())
}

fn load_credential_tx(
    connection: &Connection,
    owner: ProfileId,
) -> Result<Option<VerifiedCredential>> {
    let data: Option<Vec<u8>> = connection
        .query_row(
            "SELECT data FROM app_credentials WHERE owner=?1",
            [owner.0.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(data) = data else {
        return Ok(None);
    };
    let credential: VerifiedCredential =
        postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
    if credential.profile_id() != owner {
        return Err(Error::Unauthorized);
    }
    Ok(Some(credential))
}

fn save_peer_credential_tx(
    connection: &Connection,
    owner: ProfileId,
    credential: &VerifiedCredential,
    max_bytes: u64,
) -> Result<()> {
    let subject = credential.profile_id();
    if owner == subject {
        return Err(Error::InvalidInput);
    }
    let data = postcard::to_allocvec(credential).map_err(|_| Error::Serialization)?;
    if data.len() > 16 * 1024 {
        return Err(Error::LimitExceeded);
    }
    if let Some(previous) = load_peer_credential_tx(connection, owner, subject)? {
        if previous.claims.signing_key != credential.claims.signing_key
            || previous.claims.encryption_key != credential.claims.encryption_key
        {
            return Err(Error::Unauthorized);
        }
        if credential.claims.issued_at < previous.claims.issued_at {
            return Ok(());
        }
        if credential.claims.issued_at == previous.claims.issued_at {
            if &previous == credential {
                return Ok(());
            }
            return Err(Error::Unauthorized);
        }
    }
    if load_peer_credential_tx(connection, owner, subject)?.is_none()
        && storage_bytes(connection)?.saturating_add(data.len() as u64 + 64) > max_bytes
    {
        return Err(Error::LimitExceeded);
    }
    connection.execute(
        "INSERT INTO peer_credentials(owner,subject,data) VALUES(?1,?2,?3) ON CONFLICT(owner,subject) DO UPDATE SET data=excluded.data",
        params![owner.0.as_slice(), subject.0.as_slice(), data],
    )?;
    Ok(())
}

fn load_peer_credential_tx(
    connection: &Connection,
    owner: ProfileId,
    subject: ProfileId,
) -> Result<Option<VerifiedCredential>> {
    let data: Option<Vec<u8>> = connection
        .query_row(
            "SELECT data FROM peer_credentials WHERE owner=?1 AND subject=?2",
            params![owner.0.as_slice(), subject.0.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(data) = data else {
        return Ok(None);
    };
    let credential: VerifiedCredential =
        postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
    if credential.profile_id() != subject || owner == subject {
        return Err(Error::Unauthorized);
    }
    Ok(Some(credential))
}

fn upsert_feedback_tx(
    connection: &Connection,
    owner: ProfileId,
    peer: ProfileId,
    liked: bool,
    seen_at: u64,
    max_bytes: u64,
) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_feedback WHERE owner=?1 AND peer=?2)",
        params![owner.0.as_slice(), peer.0.as_slice()],
        |row| row.get(0),
    )?;
    if !exists && storage_bytes(connection)? + 80 > max_bytes {
        return Err(Error::LimitExceeded);
    }
    let count: u32 = connection.query_row(
        "SELECT count(*) FROM local_feedback WHERE owner=?1",
        [owner.0.as_slice()],
        |row| row.get(0),
    )?;
    if !exists && count >= 512 {
        connection.execute(
            "DELETE FROM local_feedback WHERE owner=?1 AND peer=(SELECT peer FROM local_feedback WHERE owner=?1 ORDER BY seen_at,peer LIMIT 1)",
            [owner.0.as_slice()],
        )?;
    }
    connection.execute(
        "INSERT INTO local_feedback(owner,peer,liked,seen_at) VALUES(?1,?2,?3,?4) ON CONFLICT(owner,peer) DO UPDATE SET liked=excluded.liked,seen_at=excluded.seen_at",
        params![owner.0.as_slice(), peer.0.as_slice(), liked, sql_u64(seen_at)?],
    )?;
    Ok(())
}

fn validate_operation_inputs(
    key: [u8; 32],
    payload: &[u8],
    peers: &[String],
    items: &[[u8; 32]],
    expires_at: u64,
) -> Result<()> {
    if key == [0; 32]
        || payload.is_empty()
        || payload.len() > MAX_OPERATION_BYTES
        || peers.is_empty()
        || peers.len() > MAX_OPERATION_PEERS
        || items.is_empty()
        || items.len() > MAX_OPERATION_ITEMS
        || expires_at == 0
    {
        return Err(Error::InvalidInput);
    }
    let mut unique_peers = std::collections::BTreeSet::new();
    if peers
        .iter()
        .any(|peer| validate_peer_key(peer).is_err() || !unique_peers.insert(peer))
    {
        return Err(Error::InvalidInput);
    }
    let mut unique_items = std::collections::BTreeSet::new();
    if items
        .iter()
        .any(|item| *item == [0; 32] || !unique_items.insert(item))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn operation_kind_value(kind: OutgoingOperationKind) -> i64 {
    match kind {
        OutgoingOperationKind::Publication => 1,
        OutgoingOperationKind::Like => 2,
        OutgoingOperationKind::Contact => 3,
    }
}

fn operation_status_value(status: OutgoingOperationStatus) -> i64 {
    match status {
        OutgoingOperationStatus::Pending => 0,
        OutgoingOperationStatus::Partial => 1,
        OutgoingOperationStatus::Completed => 2,
        OutgoingOperationStatus::Failed => 3,
    }
}

fn delivery_failure_value(reason: DeliveryFailureKind) -> i64 {
    match reason {
        DeliveryFailureKind::Unreachable => 1,
        DeliveryFailureKind::Rejected => 2,
        DeliveryFailureKind::Budget => 3,
        DeliveryFailureKind::Cancelled => 4,
    }
}

fn delivery_failure_kind(value: i64) -> Result<DeliveryFailureKind> {
    match value {
        1 => Ok(DeliveryFailureKind::Unreachable),
        2 => Ok(DeliveryFailureKind::Rejected),
        3 => Ok(DeliveryFailureKind::Budget),
        4 => Ok(DeliveryFailureKind::Cancelled),
        _ => Err(Error::InvalidInput),
    }
}

// These fields are intentionally explicit because one write defines the durable operation.
#[allow(clippy::too_many_arguments)]
fn insert_operation_tx(
    connection: &Connection,
    owner: ProfileId,
    kind: OutgoingOperationKind,
    idempotency_key: [u8; 32],
    related_peer: Option<ProfileId>,
    exact_payload: Vec<u8>,
    peer_targets: Vec<String>,
    items: Vec<[u8; 32]>,
    expires_at: u64,
    max_bytes: u64,
) -> Result<OperationRecord> {
    let pending: u32 = connection.query_row(
        "SELECT count(*) FROM outgoing_operations WHERE owner=?1 AND status IN (0,1)",
        [owner.0.as_slice()],
        |row| row.get(0),
    )?;
    let total: u32 = connection.query_row(
        "SELECT count(*) FROM outgoing_operations WHERE owner=?1",
        [owner.0.as_slice()],
        |row| row.get(0),
    )?;
    if pending >= MAX_PENDING_OPERATIONS_PER_OWNER || total >= MAX_OPERATIONS_PER_OWNER {
        return Err(Error::LimitExceeded);
    }
    let targets_data = postcard::to_allocvec(&peer_targets).map_err(|_| Error::Serialization)?;
    let items_data = postcard::to_allocvec(&items).map_err(|_| Error::Serialization)?;
    let extra =
        exact_payload.len() as u64 + targets_data.len() as u64 + items_data.len() as u64 + 192;
    if storage_bytes(connection)?.saturating_add(extra) > max_bytes {
        return Err(Error::LimitExceeded);
    }
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| Error::Crypto)?;
    if id == [0; 16] {
        return Err(Error::Crypto);
    }
    connection.execute(
        "INSERT INTO outgoing_operations(id,owner,kind,idempotency_key,version,related_peer,exact_payload,peer_targets,items,expires_at,status) VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9,0)",
        params![
            id.as_slice(), owner.0.as_slice(), operation_kind_value(kind), idempotency_key.as_slice(),
            related_peer.map(|profile| profile.0.to_vec()), exact_payload, targets_data, items_data,
            sql_u64(expires_at)?,
        ],
    )?;
    load_operation_tx(connection, owner, id)?.ok_or(Error::NotFound)
}

fn find_operation_by_key(
    connection: &Connection,
    owner: ProfileId,
    kind: OutgoingOperationKind,
    key: [u8; 32],
) -> Result<Option<OperationRecord>> {
    let id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT id FROM outgoing_operations WHERE owner=?1 AND kind=?2 AND idempotency_key=?3",
            params![
                owner.0.as_slice(),
                operation_kind_value(kind),
                key.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?;
    match id {
        Some(id) => {
            let id: [u8; 16] = id.try_into().map_err(|_| Error::InvalidInput)?;
            load_operation_tx(connection, owner, id)
        }
        None => Ok(None),
    }
}

fn pending_operation_ids(
    connection: &Connection,
    owner: ProfileId,
    cursor: Option<&[u8]>,
    after: bool,
    limit: usize,
) -> Result<Vec<[u8; 16]>> {
    let boundary = if after {
        "(?2 IS NULL OR id>?2)"
    } else {
        "(?2 IS NOT NULL AND id<=?2)"
    };
    let sql = format!(
        "SELECT id FROM outgoing_operations WHERE owner=?1 AND status IN (0,1) AND {boundary} ORDER BY id LIMIT ?3"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params![owner.0.as_slice(), cursor, limit as u32], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    rows.map(|row| row?.try_into().map_err(|_| Error::InvalidInput))
        .collect()
}

type CandidateEmbedding = ([u8; 32], u16, Vec<f64>);
type OperationRow = (
    i64,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
);

fn load_operation_tx(
    connection: &Connection,
    owner: ProfileId,
    id: [u8; 16],
) -> Result<Option<OperationRecord>> {
    let row: Option<OperationRow> = connection
        .query_row(
            "SELECT kind,idempotency_key,version,related_peer,exact_payload,peer_targets,items,expires_at,status FROM outgoing_operations WHERE id=?1 AND owner=?2",
            params![id.as_slice(), owner.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
        )
        .optional()?;
    let Some((kind, key, version, related_peer, payload, targets, items, expires_at, status)) = row
    else {
        return Ok(None);
    };
    let kind = match kind {
        1 => OutgoingOperationKind::Publication,
        2 => OutgoingOperationKind::Like,
        3 => OutgoingOperationKind::Contact,
        _ => return Err(Error::InvalidInput),
    };
    let idempotency_key: [u8; 32] = key.try_into().map_err(|_| Error::InvalidInput)?;
    let related_peer = related_peer
        .map(|bytes| {
            bytes
                .try_into()
                .map(ProfileId)
                .map_err(|_| Error::InvalidInput)
        })
        .transpose()?;
    let version = u16::try_from(version).map_err(|_| Error::InvalidInput)?;
    if version != 1 || payload.is_empty() || payload.len() > MAX_OPERATION_BYTES {
        return Err(Error::InvalidInput);
    }
    let peer_targets: Vec<String> =
        postcard::from_bytes(&targets).map_err(|_| Error::Serialization)?;
    let items: Vec<[u8; 32]> = postcard::from_bytes(&items).map_err(|_| Error::Serialization)?;
    let mut statement = connection.prepare(
        "SELECT a.peer_id,a.item,a.accepted,f.reason FROM operation_item_acks a LEFT JOIN operation_item_failures f ON f.operation_id=a.operation_id AND f.peer_id=a.peer_id AND f.item=a.item WHERE a.operation_id=?1 ORDER BY a.peer_id,a.item",
    )?;
    let rows = statement.query_map([id.as_slice()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, bool>(2)?,
            row.get::<_, Option<i64>>(3)?,
        ))
    })?;
    let mut peer_item_acks = Vec::new();
    for row in rows {
        let (peer_id, item, accepted, failure) = row?;
        peer_item_acks.push(PeerItemAck {
            peer_id,
            item: item.try_into().map_err(|_| Error::InvalidInput)?,
            accepted,
            failure: failure.map(delivery_failure_kind).transpose()?,
        });
    }
    let status = match status {
        0 => OutgoingOperationStatus::Pending,
        1 => OutgoingOperationStatus::Partial,
        2 => OutgoingOperationStatus::Completed,
        3 => OutgoingOperationStatus::Failed,
        _ => return Err(Error::InvalidInput),
    };
    Ok(Some(OperationRecord {
        id,
        owner,
        kind,
        idempotency_key,
        related_peer,
        version,
        exact_payload: payload,
        peer_targets,
        items,
        peer_item_acks,
        expires_at: u64::try_from(expires_at).map_err(|_| Error::InvalidInput)?,
        status,
    }))
}

fn save_checkpoint_tx(
    tx: &rusqlite::Transaction<'_>,
    owner: ProfileId,
    peer: &str,
    cursor: Option<MailboxCursor>,
) -> Result<()> {
    validate_peer_key(peer)?;
    match cursor {
        Some(cursor) => {
            tx.execute(
                "INSERT INTO sync_checkpoints(owner,peer,expires_at,parcel_id) VALUES(?1,?2,?3,?4) ON CONFLICT(owner,peer) DO UPDATE SET expires_at=excluded.expires_at,parcel_id=excluded.parcel_id",
                params![owner.0.as_slice(), peer, sql_u64(cursor.expires_at)?, cursor.parcel_id.as_slice()],
            )?;
        }
        None => {
            tx.execute(
                "DELETE FROM sync_checkpoints WHERE owner=?1 AND peer=?2",
                params![owner.0.as_slice(), peer],
            )?;
        }
    }
    Ok(())
}

fn load_notification_preferences(
    connection: &Connection,
    owner: ProfileId,
) -> Result<NotificationPreferences> {
    let row: Option<(bool, bool)> = connection
        .query_row(
            "SELECT likes_enabled,matches_enabled FROM notification_preferences WHERE owner=?1",
            [owner.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((likes_enabled, matches_enabled)) => NotificationPreferences {
            likes_enabled,
            matches_enabled,
        },
        None => NotificationPreferences::default(),
    })
}

fn notification_kind(value: i64) -> Result<NotificationKind> {
    match value {
        1 => Ok(NotificationKind::NewLike),
        2 => Ok(NotificationKind::NewMatch),
        _ => Err(Error::InvalidInput),
    }
}

fn insert_notification_tx(
    tx: &rusqlite::Transaction<'_>,
    owner: ProfileId,
    kind: NotificationKind,
    evidence: &[u8],
) -> Result<Option<NotificationEvent>> {
    let preferences = load_notification_preferences(tx, owner)?;
    if match kind {
        NotificationKind::NewLike => !preferences.likes_enabled,
        NotificationKind::NewMatch => !preferences.matches_enabled,
    } {
        return Ok(None);
    }
    let kind_value = match kind {
        NotificationKind::NewLike => 1,
        NotificationKind::NewMatch => 2,
    };
    let event_id = notification_id(owner, kind, evidence);
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM notification_outbox WHERE owner=?1 AND event_id=?2)",
        params![owner.0.as_slice(), event_id.as_slice()],
        |row| row.get(0),
    )?;
    if exists {
        return Ok(None);
    }
    let pending: u32 = tx.query_row(
        "SELECT count(*) FROM notification_outbox WHERE owner=?1 AND acknowledged=0",
        [owner.0.as_slice()],
        |row| row.get(0),
    )?;
    if pending >= MAX_NOTIFICATION_EVENTS_PER_OWNER {
        return Err(Error::LimitExceeded);
    }
    let total: u32 = tx.query_row(
        "SELECT count(*) FROM notification_outbox WHERE owner=?1",
        [owner.0.as_slice()],
        |row| row.get(0),
    )?;
    if total >= MAX_NOTIFICATION_EVENTS_PER_OWNER + MAX_NOTIFICATION_HISTORY_PER_OWNER {
        // Processed-message evidence and one-way match transitions prevent an evicted acked
        // event from being recreated when old mailbox data is replayed.
        let removed = tx.execute(
            "DELETE FROM notification_outbox WHERE owner=?1 AND event_id=(SELECT event_id FROM notification_outbox WHERE owner=?1 AND acknowledged=1 ORDER BY rowid LIMIT 1)",
            [owner.0.as_slice()],
        )?;
        if removed == 0 {
            return Err(Error::LimitExceeded);
        }
    }
    tx.execute(
        "INSERT INTO notification_outbox(owner,event_id,kind) VALUES(?1,?2,?3)",
        params![owner.0.as_slice(), event_id.as_slice(), kind_value],
    )?;
    Ok(Some(NotificationEvent { event_id, kind }))
}

fn notification_id(owner: ProfileId, kind: NotificationKind, evidence: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"annoda/notification-event/v1\0");
    hasher.update(&owner.0);
    hasher.update(&[match kind {
        NotificationKind::NewLike => 1,
        NotificationKind::NewMatch => 2,
    }]);
    hasher.update(evidence);
    *hasher.finalize().as_bytes()
}

fn like_evidence(sender: ProfileId, id: [u8; 16]) -> [u8; 48] {
    let mut evidence = [0; 48];
    evidence[..32].copy_from_slice(&sender.0);
    evidence[32..].copy_from_slice(&id);
    evidence
}

fn storage_bytes(connection: &Connection) -> Result<u64> {
    let value: i64 = connection.query_row(
        "SELECT COALESCE((SELECT sum(length(data)+48) FROM profiles),0)
         +COALESCE((SELECT sum(length(data)+32) FROM blobs),0)
         +COALESCE((SELECT sum(length(data)+56) FROM mailbox),0)
         +COALESCE((SELECT sum(length(authorization)+72) FROM photo_leases),0)
         +COALESCE((SELECT sum(length(id)+length(recipient)+8) FROM seen_messages),0)
         +COALESCE((SELECT sum(length(data)+32) FROM app_credentials),0)
         +COALESCE((SELECT sum(length(data)+64) FROM peer_credentials),0)
         +COALESCE((SELECT sum(length(exact_payload)+length(peer_targets)+length(items)+160) FROM outgoing_operations),0)
         +COALESCE((SELECT sum(length(peer_id)+length(item)+48) FROM operation_item_acks),0)
         +COALESCE((SELECT count(*)*32 FROM operation_item_failures),0)
         +COALESCE((SELECT count(*)*48 FROM operation_drain_cursor),0)
         +COALESCE((SELECT sum(length(data)+64) FROM candidate_cache),0)
         +COALESCE((SELECT sum(length(data)+96) FROM candidate_embeddings),0)
         +COALESCE((SELECT sum(length(data)+64) FROM local_reports),0)
         +COALESCE((SELECT sum(length(data)+32) FROM preference_models),0)
         +COALESCE((SELECT sum(length(peer)+16) FROM local_feedback),0)
         +COALESCE((SELECT sum(length(peer)+16) FROM trained_feedback),0)",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(value).map_err(|_| Error::LimitExceeded)
}

fn load_match_tx(
    connection: &Connection,
    owner: ProfileId,
    peer: ProfileId,
) -> Result<Option<MatchRecord>> {
    let data: Option<Vec<u8>> = connection
        .query_row(
            "SELECT data FROM match_state WHERE owner=?1 AND peer=?2",
            params![owner.0.as_slice(), peer.0.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(data) = data else {
        return Ok(None);
    };
    let snapshot: PersistedMatch = postcard::from_bytes(&data).map_err(|_| Error::Serialization)?;
    if snapshot.owner != owner || snapshot.peer != peer {
        return Err(Error::InvalidInput);
    }
    Ok(Some(MatchRecord::from_persisted(
        snapshot.owner,
        snapshot.peer,
        snapshot.state,
        snapshot.local_like_id,
        snapshot.remote_like_id,
    )?))
}

fn save_match_tx(connection: &Connection, record: &MatchRecord) -> Result<()> {
    if !record.has_valid_evidence() {
        return Err(Error::InvalidInput);
    }
    if let Some(previous) = load_match_tx(connection, record.owner(), record.peer())?
        && !valid_match_transition(&previous, record)
    {
        return Err(Error::Unauthorized);
    }
    let data = postcard::to_allocvec(&PersistedMatch {
        owner: record.owner(),
        peer: record.peer(),
        state: record.state(),
        local_like_id: record.local_like_id(),
        remote_like_id: record.remote_like_id(),
    })
    .map_err(|_| Error::Serialization)?;
    let state = match record.state() {
        MatchState::Neutral => 0,
        MatchState::Outgoing => 1,
        MatchState::Incoming => 2,
        MatchState::Matched => 3,
        MatchState::Rejected => 4,
        MatchState::Blocked => 5,
    };
    connection.execute(
        "INSERT INTO match_state(owner,peer,state,data) VALUES(?1,?2,?3,?4) ON CONFLICT(owner,peer) DO UPDATE SET state=excluded.state,data=excluded.data",
        params![record.owner().0.as_slice(), record.peer().0.as_slice(), state, data],
    )?;
    Ok(())
}

fn valid_match_transition(previous: &MatchRecord, next: &MatchRecord) -> bool {
    use MatchState::*;
    let evidence_preserved = previous
        .local_like_id()
        .is_none_or(|id| next.local_like_id() == Some(id))
        && previous
            .remote_like_id()
            .is_none_or(|id| next.remote_like_id() == Some(id));
    evidence_preserved
        && match previous.state() {
            Neutral => true,
            Outgoing => matches!(next.state(), Outgoing | Matched | Rejected | Blocked),
            Incoming => matches!(next.state(), Incoming | Matched | Rejected | Blocked),
            Matched => matches!(next.state(), Matched | Blocked),
            Rejected => matches!(next.state(), Rejected | Blocked),
            Blocked => next.state() == Blocked,
        }
}

fn sql_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::LimitExceeded)
}

#[cfg(test)]
#[path = "tests/storage.rs"]
mod tests;
