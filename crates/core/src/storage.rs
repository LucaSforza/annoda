use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    identity::{DeviceKeyPair, TrustedIssuers, VerifiedCredential, canonical, verify_signature},
    matching::{ContactDisclosure, MatchRecord, MatchState},
    protocol::{
        ContentHash, ContentLease, MailboxParcel, MessageEnvelope, MessageKind, ProfileId,
        PublicProfile,
    },
};

pub use crate::notifications::{NotificationEvent, NotificationKind, NotificationPreferences};

const POLL_DOMAIN: &[u8] = b"annoda/mailbox-poll/v1\0";
const MAX_NOTIFICATION_EVENTS_PER_OWNER: u32 = 4096;
const MAX_NOTIFICATION_HISTORY_PER_OWNER: u32 = 4096;
const MAX_CHECKPOINT_PEER_ID_BYTES: usize = 256;
const MAX_SYNC_REJECTIONS_PER_OWNER: u32 = 8192;

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
        Ok(Self { connection, limits })
    }

    pub fn open_default(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path, StorageLimits::default())
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
         +COALESCE((SELECT sum(length(id)+length(recipient)+8) FROM seen_messages),0)",
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
