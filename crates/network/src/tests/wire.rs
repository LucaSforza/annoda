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
