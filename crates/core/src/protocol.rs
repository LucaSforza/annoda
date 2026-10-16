use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    identity::{
        DeviceKeyPair, TrustedIssuers, VerifiedCredential, canonical, seal, verify_signature,
    },
};

const PROFILE_DOMAIN: &[u8] = b"annoda/profile/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"annoda/envelope/v1\0";
const LEASE_DOMAIN: &[u8] = b"annoda/content-lease/v1\0";
pub const MAX_PROFILE_BYTES: usize = 16 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
pub const MAX_MAILBOX_PARCEL_BYTES: usize = MAX_ENVELOPE_BYTES + 1024;
pub const MAX_PROFILE_PHOTOS: usize = 6;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct ProfileId(pub [u8; 32]);

impl ProfileId {
    pub fn from_signing_key(key: &[u8; 32]) -> Self {
        Self(*blake3::hash(key).as_bytes())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    pub fn digest(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PhotoManifest {
    pub hash: ContentHash,
    pub byte_count: u32,
    pub media_type: String,
}

impl PhotoManifest {
    pub fn from_bytes(bytes: &[u8], media_type: &str) -> Result<Self> {
        if bytes.is_empty()
            || bytes.len() > 4 * 1024 * 1024
            || bytes.len() > u32::MAX as usize
            || !matches!(media_type, "image/jpeg" | "image/png")
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            hash: ContentHash::digest(bytes),
            byte_count: bytes.len() as u32,
            media_type: media_type.to_owned(),
        })
    }

    pub fn verifies(&self, bytes: &[u8]) -> bool {
        self.byte_count as usize == bytes.len() && ContentHash::digest(bytes) == self.hash
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PublicProfile {
    pub version: u16,
    pub revision: u64,
    pub owner: ProfileId,
    pub credential: VerifiedCredential,
    pub photos: Vec<PhotoManifest>,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
struct ProfileClaims {
    version: u16,
    revision: u64,
    owner: ProfileId,
    credential: VerifiedCredential,
    photos: Vec<PhotoManifest>,
    expires_at: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Like,
    ContactDisclosure,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct MessageEnvelope {
    pub version: u16,
    pub id: [u8; 16],
    pub kind: MessageKind,
    pub sender: ProfileId,
    pub recipient: ProfileId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct EnvelopeClaims<'a> {
    version: u16,
    id: [u8; 16],
    kind: MessageKind,
    sender: ProfileId,
    recipient: ProfileId,
    issued_at: u64,
    expires_at: u64,
    ciphertext: &'a [u8],
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ContentLease {
    pub owner: ProfileId,
    pub hash: ContentHash,
    pub byte_count: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct LeaseClaims {
    owner: ProfileId,
    hash: ContentHash,
    byte_count: u32,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct StoredMessage {
    pub envelope: MessageEnvelope,
    pub sender_credential: VerifiedCredential,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct MailboxParcel {
    pub version: u16,
    pub id: [u8; 16],
    pub recipient: ProfileId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize)]
struct MailboxAad {
    version: u16,
    id: [u8; 16],
    recipient: ProfileId,
    issued_at: u64,
    expires_at: u64,
}

impl PublicProfile {
    pub fn create(
        device: &DeviceKeyPair,
        credential: VerifiedCredential,
        photos: Vec<PhotoManifest>,
        expires_at: u64,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Self> {
        Self::create_revisioned(device, credential, photos, 1, expires_at, issuers, now)
    }

    pub fn create_revisioned(
        device: &DeviceKeyPair,
        credential: VerifiedCredential,
        photos: Vec<PhotoManifest>,
        revision: u64,
        expires_at: u64,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Self> {
        credential.verify(issuers, now)?;
        if credential.profile_id() != device.profile_id()
            || credential.claims.signing_key != device.signing_public_key()
            || credential.claims.encryption_key != device.encryption_public_key()
            || expires_at <= now
            || expires_at > credential.claims.expires_at
            || photos.len() > MAX_PROFILE_PHOTOS
            || revision == 0
        {
            return Err(Error::InvalidInput);
        }
        let claims = ProfileClaims {
            version: 1,
            revision,
            owner: device.profile_id(),
            credential,
            photos,
            expires_at,
        };
        let bytes = canonical(PROFILE_DOMAIN, &claims)?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(Error::LimitExceeded);
        }
        let signature = device.sign(b"annoda/profile-signature/v1\0", &bytes);
        Ok(Self {
            version: claims.version,
            revision: claims.revision,
            owner: claims.owner,
            credential: claims.credential,
            photos: claims.photos,
            expires_at,
            signature,
        })
    }

    pub fn verify(&self, issuers: &TrustedIssuers, now: u64) -> Result<()> {
        self.credential.verify(issuers, now)?;
        if self.version != 1
            || self.owner != self.credential.profile_id()
            || self.owner != ProfileId::from_signing_key(&self.credential.claims.signing_key)
            || self.expires_at <= now
            || self.expires_at > self.credential.claims.expires_at
            || self.photos.len() > MAX_PROFILE_PHOTOS
            || self.photos.iter().any(|p| {
                p.byte_count == 0
                    || p.byte_count > 4 * 1024 * 1024
                    || !matches!(p.media_type.as_str(), "image/jpeg" | "image/png")
            })
        {
            return Err(Error::InvalidInput);
        }
        if self.revision == 0 {
            return Err(Error::InvalidInput);
        }
        let claims = ProfileClaims {
            version: self.version,
            revision: self.revision,
            owner: self.owner,
            credential: self.credential.clone(),
            photos: self.photos.clone(),
            expires_at: self.expires_at,
        };
        let bytes = canonical(PROFILE_DOMAIN, &claims)?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(Error::LimitExceeded);
        }
        verify_signature(
            &self.credential.claims.signing_key,
            b"annoda/profile-signature/v1\0",
            &bytes,
            &self.signature,
        )
    }
}

impl MessageEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        sender_device: &DeviceKeyPair,
        sender_credential: &VerifiedCredential,
        recipient: &VerifiedCredential,
        kind: MessageKind,
        id: [u8; 16],
        issued_at: u64,
        expires_at: u64,
        plaintext: &[u8],
        issuers: &TrustedIssuers,
    ) -> Result<Self> {
        sender_credential.verify(issuers, issued_at)?;
        recipient.verify(issuers, issued_at)?;
        if sender_credential.profile_id() != sender_device.profile_id()
            || sender_credential.claims.signing_key != sender_device.signing_public_key()
            || sender_credential.claims.encryption_key != sender_device.encryption_public_key()
            || expires_at <= issued_at
            || expires_at - issued_at > 30 * 24 * 60 * 60
            || expires_at > sender_credential.claims.expires_at
            || expires_at > recipient.claims.expires_at
            || plaintext.len() > MAX_ENVELOPE_BYTES
        {
            return Err(Error::InvalidInput);
        }
        let ciphertext = seal(
            &recipient.claims.encryption_key,
            b"annoda/1/private-message",
            plaintext,
        )?;
        let mut envelope = Self {
            version: 1,
            id,
            kind,
            sender: sender_device.profile_id(),
            recipient: recipient.profile_id(),
            issued_at,
            expires_at,
            ciphertext,
            signature: Vec::new(),
        };
        envelope.signature =
            sender_device.sign(b"annoda/envelope-signature/v1\0", &envelope.signed_bytes()?);
        if envelope.ciphertext.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::LimitExceeded);
        }
        Ok(envelope)
    }

    pub fn verify(
        &self,
        sender_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<()> {
        sender_credential.verify(issuers, now)?;
        if self.version != 1
            || self.sender != sender_credential.profile_id()
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 30 * 24 * 60 * 60
            || self.expires_at > sender_credential.claims.expires_at
            || self.ciphertext.len() > MAX_ENVELOPE_BYTES
        {
            return Err(Error::InvalidInput);
        }
        verify_signature(
            &sender_credential.claims.signing_key,
            b"annoda/envelope-signature/v1\0",
            &self.signed_bytes()?,
            &self.signature,
        )
    }

    pub fn open(
        &self,
        recipient_device: &DeviceKeyPair,
        sender_credential: &VerifiedCredential,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Vec<u8>> {
        self.verify(sender_credential, issuers, now)?;
        recipient_credential.verify(issuers, now)?;
        if self.recipient != recipient_device.profile_id()
            || self.recipient != recipient_credential.profile_id()
            || recipient_credential.claims.signing_key != recipient_device.signing_public_key()
            || recipient_credential.claims.encryption_key
                != recipient_device.encryption_public_key()
        {
            return Err(Error::Unauthorized);
        }
        recipient_device.open(b"annoda/1/private-message", &self.ciphertext)
    }

    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        canonical(
            ENVELOPE_DOMAIN,
            &EnvelopeClaims {
                version: self.version,
                id: self.id,
                kind: self.kind,
                sender: self.sender,
                recipient: self.recipient,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                ciphertext: &self.ciphertext,
            },
        )
    }
}

impl MailboxParcel {
    pub fn create(
        envelope: &MessageEnvelope,
        sender_credential: &VerifiedCredential,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<Self> {
        envelope.verify(sender_credential, issuers, now)?;
        recipient_credential.verify(issuers, now)?;
        if envelope.recipient != recipient_credential.profile_id()
            || envelope.expires_at > recipient_credential.claims.expires_at
        {
            return Err(Error::Unauthorized);
        }
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|_| Error::Crypto)?;
        let aad = MailboxAad {
            version: 1,
            id,
            recipient: envelope.recipient,
            issued_at: envelope.issued_at,
            expires_at: envelope.expires_at,
        };
        let plaintext = postcard::to_allocvec(&StoredMessage {
            envelope: envelope.clone(),
            sender_credential: sender_credential.clone(),
        })
        .map_err(|_| Error::Serialization)?;
        let ciphertext = seal(
            &recipient_credential.claims.encryption_key,
            &canonical(b"annoda/mailbox-parcel/v1\0", &aad)?,
            &plaintext,
        )?;
        if ciphertext.len() > MAX_MAILBOX_PARCEL_BYTES {
            return Err(Error::LimitExceeded);
        }
        Ok(Self {
            version: 1,
            id,
            recipient: envelope.recipient,
            issued_at: envelope.issued_at,
            expires_at: envelope.expires_at,
            ciphertext,
        })
    }

    pub fn verify_header(&self, now: u64) -> Result<()> {
        if self.version != 1
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 30 * 24 * 60 * 60
            || self.issued_at > now
            || self.expires_at <= now
            || self.ciphertext.len() > MAX_MAILBOX_PARCEL_BYTES
        {
            return Err(Error::InvalidTime);
        }
        Ok(())
    }

    pub fn open(
        &self,
        recipient_device: &DeviceKeyPair,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<StoredMessage> {
        self.verify_header(now)?;
        recipient_credential.verify(issuers, now)?;
        if self.recipient != recipient_credential.profile_id()
            || self.recipient != recipient_device.profile_id()
            || recipient_credential.claims.signing_key != recipient_device.signing_public_key()
            || recipient_credential.claims.encryption_key
                != recipient_device.encryption_public_key()
            || self.expires_at > recipient_credential.claims.expires_at
        {
            return Err(Error::Unauthorized);
        }
        let aad = MailboxAad {
            version: self.version,
            id: self.id,
            recipient: self.recipient,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        let aad = canonical(b"annoda/mailbox-parcel/v1\0", &aad)?;
        let plaintext = recipient_device.open(&aad, &self.ciphertext)?;
        let message: StoredMessage =
            postcard::from_bytes(&plaintext).map_err(|_| Error::Serialization)?;
        if message.envelope.recipient != self.recipient
            || message.envelope.issued_at != self.issued_at
            || message.envelope.expires_at != self.expires_at
        {
            return Err(Error::Unauthorized);
        }
        message
            .envelope
            .verify(&message.sender_credential, issuers, now)?;
        Ok(message)
    }
}

impl ContentLease {
    pub fn issue(
        device: &DeviceKeyPair,
        credential: &VerifiedCredential,
        manifest: &PhotoManifest,
        issued_at: u64,
        expires_at: u64,
        issuers: &TrustedIssuers,
    ) -> Result<Self> {
        credential.verify(issuers, issued_at)?;
        if credential.profile_id() != device.profile_id()
            || credential.claims.signing_key != device.signing_public_key()
            || manifest.byte_count == 0
            || expires_at <= issued_at
            || expires_at - issued_at > 90 * 24 * 60 * 60
            || expires_at > credential.claims.expires_at
        {
            return Err(Error::InvalidInput);
        }
        let claims = LeaseClaims {
            owner: device.profile_id(),
            hash: manifest.hash,
            byte_count: manifest.byte_count,
            issued_at,
            expires_at,
        };
        let bytes = canonical(LEASE_DOMAIN, &claims)?;
        let signature = device.sign(b"annoda/content-lease-signature/v1\0", &bytes);
        Ok(Self {
            owner: claims.owner,
            hash: claims.hash,
            byte_count: claims.byte_count,
            issued_at,
            expires_at,
            signature,
        })
    }

    pub fn verify(
        &self,
        credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<()> {
        credential.verify(issuers, now)?;
        if self.owner != credential.profile_id()
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 90 * 24 * 60 * 60
            || self.expires_at > credential.claims.expires_at
            || self.byte_count == 0
            || self.byte_count > 4 * 1024 * 1024
        {
            return Err(Error::InvalidInput);
        }
        let claims = LeaseClaims {
            owner: self.owner,
            hash: self.hash,
            byte_count: self.byte_count,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        verify_signature(
            &credential.claims.signing_key,
            b"annoda/content-lease-signature/v1\0",
            &canonical(LEASE_DOMAIN, &claims)?,
            &self.signature,
        )
    }
}

#[cfg(test)]
#[path = "tests/protocol.rs"]
mod tests;
