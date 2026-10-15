use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{StreamProtocol, request_response};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use annoda_core::{
    identity::VerifiedCredential,
    protocol::{ContentHash, ContentLease, MailboxParcel, PhotoManifest, ProfileId, PublicProfile},
};

/// The total request/response frame ceiling; checked before decoding or allocation.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MAILBOX_BATCH: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    PutProfile {
        profile: PublicProfile,
    },
    GetProfile {
        owner: ProfileId,
    },
    PutPhoto {
        manifest: PhotoManifest,
        lease: ContentLease,
        owner: VerifiedCredential,
        blob: Vec<u8>,
    },
    GetPhoto {
        owner: ProfileId,
        hash: ContentHash,
    },
    DepositMailbox {
        parcel: MailboxParcel,
    },
    PollMailbox {
        recipient: VerifiedCredential,
        challenge: [u8; 32],
        proof: Vec<u8>,
        proof_time: u64,
        limit: u16,
    },
    ListProfiles {
        limit: u16,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    Ack,
    Duplicate,
    Profile(Option<Box<PublicProfile>>),
    Profiles(Vec<PublicProfile>),
    Photo(Option<Vec<u8>>),
    Mailbox(Vec<MailboxParcel>),
    Error { code: RpcErrorCode },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum RpcErrorCode {
    Invalid,
    Unauthorized,
    Expired,
    Capacity,
    Internal,
}

impl RpcRequest {
    pub(crate) fn validate_frame_size(&self) -> bool {
        postcard::to_allocvec(self).is_ok_and(|frame| frame.len() <= MAX_FRAME_BYTES)
    }
}

#[derive(Clone, Default)]
pub(crate) struct AnnodaCodec;

#[allow(clippy::manual_async_fn)]
impl request_response::Codec for AnnodaCodec {
    type Protocol = StreamProtocol;
    type Request = RpcRequest;
    type Response = RpcResponse;

    fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> impl std::future::Future<Output = io::Result<Self::Request>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        async move { read_frame(io).await }
    }

    fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> impl std::future::Future<Output = io::Result<Self::Response>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        async move { read_frame(io).await }
    }

    fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        async move { write_frame(io, &request).await }
    }

    fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        response: Self::Response,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        async move { write_frame(io, &response).await }
    }
}

async fn read_frame<T, M>(io: &mut T) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: DeserializeOwned,
{
    let mut length_bytes = [0; 4];
    io.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Annoda frame exceeds limit",
        ));
    }
    let mut frame = vec![0; length];
    io.read_exact(&mut frame).await?;
    let (message, trailing) = postcard::take_from_bytes(&frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Annoda frame"))?;
    if !trailing.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Annoda frame has trailing bytes",
        ));
    }
    Ok(message)
}

async fn write_frame<T, M>(io: &mut T, message: &M) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: Serialize,
{
    let frame = postcard::to_allocvec(message)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cannot encode Annoda frame"))?;
    if frame.len() > MAX_FRAME_BYTES || frame.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Annoda frame exceeds limit",
        ));
    }
    io.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    io.write_all(&frame).await?;
    io.flush().await
}

pub(crate) fn frame_len<M: Serialize>(message: &M) -> usize {
    postcard::to_allocvec(message).map_or(usize::MAX, |frame| frame.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_binary_frames_preserve_photo_bytes_without_json_expansion() {
        let photo = RpcRequest::PutPhoto {
            manifest: PhotoManifest {
                hash: ContentHash([0; 32]),
                byte_count: 4 * 1024 * 1024,
                media_type: "image/jpeg".into(),
            },
            lease: ContentLease {
                owner: ProfileId([0; 32]),
                hash: ContentHash([0; 32]),
                byte_count: 4 * 1024 * 1024,
                issued_at: 1,
                expires_at: 2,
                signature: vec![0; 64],
            },
            owner: VerifiedCredential {
                claims: annoda_core::identity::CredentialClaims {
                    version: 1,
                    serial: [0; 16],
                    issuer_id: [0; 32],
                    subject: ProfileId([0; 32]),
                    signing_key: [0; 32],
                    encryption_key: vec![0; 32],
                    first_name: "Test".into(),
                    age_at_issue: 18,
                    issued_at: 1,
                    expires_at: 2,
                },
                signature: vec![0; 64],
            },
            blob: vec![7; 4 * 1024 * 1024],
        };
        assert!(photo.validate_frame_size());
        assert!(frame_len(&photo) <= 4 * 1024 * 1024 + 512);
    }

    async fn frame_from_bytes(bytes: &[u8]) -> io::Result<RpcResponse> {
        let mut reader = futures::io::Cursor::new(bytes.to_vec());
        read_frame(&mut reader).await
    }

    #[tokio::test]
    async fn rejects_oversized_truncated_and_trailing_frames() {
        let oversized = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        assert_eq!(
            frame_from_bytes(&oversized).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            frame_from_bytes(&[0, 0]).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let truncated_body = [0, 0, 0, 5, 1, 2];
        assert_eq!(
            frame_from_bytes(&truncated_body).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        let mut trailing = postcard::to_allocvec(&RpcResponse::Ack).unwrap();
        trailing.push(0);
        let mut framed = (trailing.len() as u32).to_be_bytes().to_vec();
        framed.extend(trailing);
        assert_eq!(
            frame_from_bytes(&framed).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
