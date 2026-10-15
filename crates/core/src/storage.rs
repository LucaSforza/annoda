use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    identity::{DeviceKeyPair, TrustedIssuers, VerifiedCredential, canonical, verify_signature},
    matching::{MatchRecord, MatchState},
    protocol::{
        ContentHash, ContentLease, MailboxParcel, MessageEnvelope, ProfileId, PublicProfile,
    },
};

const POLL_DOMAIN: &[u8] = b"annoda/mailbox-poll/v1\0";

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
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS profiles (id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=32), data BLOB NOT NULL, expires_at INTEGER NOT NULL, revision INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS blobs (hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash)=32), data BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS photo_leases (owner BLOB NOT NULL CHECK(length(owner)=32), hash BLOB NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE, expires_at INTEGER NOT NULL, authorization BLOB NOT NULL, PRIMARY KEY(owner,hash));
             CREATE TABLE IF NOT EXISTS mailbox (id BLOB NOT NULL CHECK(length(id)=16), recipient BLOB NOT NULL CHECK(length(recipient)=32), expires_at INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id,recipient));
             CREATE INDEX IF NOT EXISTS mailbox_recipient_expiry ON mailbox(recipient, expires_at);
             CREATE TABLE IF NOT EXISTS seen_messages (id BLOB NOT NULL CHECK(length(id)=16), recipient BLOB NOT NULL CHECK(length(recipient)=32), expires_at INTEGER NOT NULL, PRIMARY KEY(id,recipient));
             CREATE TABLE IF NOT EXISTS match_state (owner BLOB NOT NULL CHECK(length(owner)=32), peer BLOB NOT NULL CHECK(length(peer)=32), state INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(owner,peer));
             CREATE TABLE IF NOT EXISTS processed_likes (recipient BLOB NOT NULL CHECK(length(recipient)=32), sender BLOB NOT NULL CHECK(length(sender)=32), id BLOB NOT NULL CHECK(length(id)=16), PRIMARY KEY(recipient,sender,id));"
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load_match_tx(&tx, owner, peer)?.unwrap_or(MatchRecord::new(owner, peer)?);
        record.like(id)?;
        save_match_tx(&tx, &record)?;
        tx.commit()?;
        Ok(record)
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
        envelope.verify(sender_credential, issuers, now)?;
        if envelope.recipient != recipient_credential.profile_id() {
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
            return load_match_tx(&tx, envelope.recipient, envelope.sender)?.ok_or(Error::NotFound);
        }
        let mut candidate = load_match_tx(&tx, envelope.recipient, envelope.sender)?
            .unwrap_or(MatchRecord::new(envelope.recipient, envelope.sender)?);
        candidate.receive_envelope(
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
        tx.commit()?;
        Ok(candidate)
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
        tx.execute("DELETE FROM photo_leases WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM profiles WHERE expires_at<=?1", [now])?;
        tx.execute("DELETE FROM blobs WHERE NOT EXISTS(SELECT 1 FROM photo_leases WHERE photo_leases.hash=blobs.hash)", [])?;
        tx.commit()?;
        Ok(())
    }
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
mod tests {
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
        let lease =
            ContentLease::issue(&owner, &credential, &manifest, 20, 90, &trust).expect("lease");
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
        let lease =
            ContentLease::issue(&owner, &credential, &manifest, 20, 90, &trust).expect("lease");
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
}
