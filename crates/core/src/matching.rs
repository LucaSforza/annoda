use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    identity::{DeviceKeyPair, TrustedIssuers, VerifiedCredential},
    protocol::{MessageEnvelope, MessageKind, ProfileId},
};

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum MatchState {
    Neutral,
    Outgoing,
    Incoming,
    Matched,
    Rejected,
    Blocked,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum ContactService {
    Instagram,
    Telegram,
    WhatsApp,
    Other(String),
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ContactHandle {
    pub service: ContactService,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchRecord {
    owner: ProfileId,
    peer: ProfileId,
    state: MatchState,
    local_like_id: Option<[u8; 16]>,
    remote_like_id: Option<[u8; 16]>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct LikeIntent {
    pub sender: ProfileId,
    pub recipient: ProfileId,
    pub id: [u8; 16],
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct ContactDisclosure {
    pub match_id: [u8; 32],
    pub sender: ProfileId,
    pub recipient: ProfileId,
    pub handles: Vec<ContactHandle>,
}

impl MatchRecord {
    pub fn new(owner: ProfileId, peer: ProfileId) -> Result<Self> {
        if owner == peer {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            owner,
            peer,
            state: MatchState::Neutral,
            local_like_id: None,
            remote_like_id: None,
        })
    }

    pub fn owner(&self) -> ProfileId {
        self.owner
    }
    pub fn peer(&self) -> ProfileId {
        self.peer
    }
    pub fn state(&self) -> MatchState {
        self.state
    }
    pub fn local_like_id(&self) -> Option<[u8; 16]> {
        self.local_like_id
    }
    pub fn remote_like_id(&self) -> Option<[u8; 16]> {
        self.remote_like_id
    }

    pub(crate) fn from_persisted(
        owner: ProfileId,
        peer: ProfileId,
        state: MatchState,
        local_like_id: Option<[u8; 16]>,
        remote_like_id: Option<[u8; 16]>,
    ) -> Result<Self> {
        let record = Self {
            owner,
            peer,
            state,
            local_like_id,
            remote_like_id,
        };
        if !record.has_valid_evidence() {
            return Err(Error::InvalidInput);
        }
        Ok(record)
    }

    pub fn like(&mut self, id: [u8; 16]) -> Result<bool> {
        match self.state {
            MatchState::Neutral => {
                self.local_like_id = Some(id);
                self.state = MatchState::Outgoing;
                Ok(true)
            }
            MatchState::Incoming => {
                self.local_like_id = Some(id);
                self.state = MatchState::Matched;
                Ok(true)
            }
            MatchState::Outgoing | MatchState::Matched => Ok(false),
            MatchState::Rejected | MatchState::Blocked => Err(Error::Unauthorized),
        }
    }

    fn receive_like(
        &mut self,
        sender: ProfileId,
        recipient: ProfileId,
        id: [u8; 16],
    ) -> Result<bool> {
        if sender != self.peer || recipient != self.owner {
            return Err(Error::Unauthorized);
        }
        match self.state {
            MatchState::Neutral => {
                self.remote_like_id = Some(id);
                self.state = MatchState::Incoming;
                Ok(true)
            }
            MatchState::Outgoing => {
                self.remote_like_id = Some(id);
                self.state = MatchState::Matched;
                Ok(true)
            }
            MatchState::Incoming | MatchState::Matched => {
                if self.remote_like_id == Some(id) {
                    Ok(false)
                } else {
                    Err(Error::Unauthorized)
                }
            }
            MatchState::Rejected | MatchState::Blocked => Ok(false),
        }
    }

    pub fn receive_envelope(
        &mut self,
        envelope: &MessageEnvelope,
        sender_credential: &VerifiedCredential,
        recipient_device: &DeviceKeyPair,
        recipient_credential: &VerifiedCredential,
        issuers: &TrustedIssuers,
        now: u64,
    ) -> Result<bool> {
        if envelope.kind != MessageKind::Like || envelope.id == [0; 16] {
            return Err(Error::InvalidInput);
        }
        let bytes = envelope.open(
            recipient_device,
            sender_credential,
            recipient_credential,
            issuers,
            now,
        )?;
        let intent: LikeIntent = postcard::from_bytes(&bytes).map_err(|_| Error::Serialization)?;
        if intent.id != envelope.id
            || intent.sender != envelope.sender
            || intent.recipient != envelope.recipient
            || self.owner != recipient_device.profile_id()
            || self.owner != recipient_credential.profile_id()
        {
            return Err(Error::Unauthorized);
        }
        self.receive_like(intent.sender, intent.recipient, intent.id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_like_envelope(
        &mut self,
        device: &DeviceKeyPair,
        sender_credential: &VerifiedCredential,
        recipient: &VerifiedCredential,
        id: [u8; 16],
        now: u64,
        expires_at: u64,
        issuers: &TrustedIssuers,
    ) -> Result<MessageEnvelope> {
        if self.owner != device.profile_id() || self.peer != recipient.profile_id() {
            return Err(Error::Unauthorized);
        }
        let payload = postcard::to_allocvec(&LikeIntent {
            sender: self.owner,
            recipient: self.peer,
            id,
        })
        .map_err(|_| Error::Serialization)?;
        let envelope = MessageEnvelope::create(
            device,
            sender_credential,
            recipient,
            MessageKind::Like,
            id,
            now,
            expires_at,
            &payload,
            issuers,
        )?;
        self.like(id)?;
        Ok(envelope)
    }

    pub fn reject(&mut self) -> Result<()> {
        match self.state {
            MatchState::Matched | MatchState::Blocked => Err(Error::Unauthorized),
            _ => {
                self.state = MatchState::Rejected;
                Ok(())
            }
        }
    }

    pub fn block(&mut self) {
        self.state = MatchState::Blocked;
    }

    pub fn match_id(&self) -> Result<[u8; 32]> {
        if self.state != MatchState::Matched {
            return Err(Error::Unauthorized);
        }
        let local = self.local_like_id.ok_or(Error::Unauthorized)?;
        let remote = self.remote_like_id.ok_or(Error::Unauthorized)?;
        let (first, second, first_like, second_like) = if self.owner < self.peer {
            (self.owner, self.peer, local, remote)
        } else {
            (self.peer, self.owner, remote, local)
        };
        let bytes = postcard::to_allocvec(&(first, second, first_like, second_like))
            .map_err(|_| Error::Serialization)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"annoda/match-id/v1\0");
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn has_valid_evidence(&self) -> bool {
        if self.owner == self.peer {
            return false;
        }
        match self.state {
            MatchState::Neutral => self.local_like_id.is_none() && self.remote_like_id.is_none(),
            MatchState::Outgoing => self.local_like_id.is_some() && self.remote_like_id.is_none(),
            MatchState::Incoming => self.local_like_id.is_none() && self.remote_like_id.is_some(),
            MatchState::Matched => self.local_like_id.is_some() && self.remote_like_id.is_some(),
            MatchState::Rejected | MatchState::Blocked => true,
        }
    }

    pub fn disclose(&self, handles: Vec<ContactHandle>) -> Result<ContactDisclosure> {
        if self.state != MatchState::Matched {
            return Err(Error::Unauthorized);
        }
        validate_handles(&handles)?;
        Ok(ContactDisclosure {
            match_id: self.match_id()?,
            sender: self.owner,
            recipient: self.peer,
            handles,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encrypted_disclosure(
        &self,
        device: &DeviceKeyPair,
        sender_credential: &VerifiedCredential,
        recipient: &VerifiedCredential,
        handles: Vec<ContactHandle>,
        id: [u8; 16],
        now: u64,
        expires_at: u64,
        issuers: &TrustedIssuers,
    ) -> Result<MessageEnvelope> {
        if self.state != MatchState::Matched
            || self.owner != device.profile_id()
            || self.peer != recipient.profile_id()
        {
            return Err(Error::Unauthorized);
        }
        let disclosure = self.disclose(handles)?;
        let payload = postcard::to_allocvec(&disclosure).map_err(|_| Error::Serialization)?;
        MessageEnvelope::create(
            device,
            sender_credential,
            recipient,
            MessageKind::ContactDisclosure,
            id,
            now,
            expires_at,
            &payload,
            issuers,
        )
    }
}

impl ContactDisclosure {
    pub fn decode(
        bytes: &[u8],
        sender: ProfileId,
        recipient: ProfileId,
        match_id: [u8; 32],
    ) -> Result<Self> {
        let disclosure: Self = postcard::from_bytes(bytes).map_err(|_| Error::Serialization)?;
        if disclosure.sender != sender
            || disclosure.recipient != recipient
            || disclosure.match_id != match_id
        {
            return Err(Error::Unauthorized);
        }
        validate_handles(&disclosure.handles)?;
        Ok(disclosure)
    }
}

pub fn validate_handles(handles: &[ContactHandle]) -> Result<()> {
    if handles.is_empty() || handles.len() > 8 {
        return Err(Error::InvalidInput);
    }
    for handle in handles {
        let value = handle.value.trim();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(Error::InvalidInput);
        }
        if let ContactService::Other(service) = &handle.service
            && (service.trim().is_empty()
                || service.len() > 64
                || service.chars().any(char::is_control))
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/matching.rs"]
mod tests;
