use super::*;
use image::{ImageBuffer, Rgb};

fn jpeg() -> Vec<u8> {
    let image = ImageBuffer::from_pixel(8, 6, Rgb([22, 40, 80]));
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(image)
        .write_to(&mut bytes, ImageFormat::Jpeg)
        .unwrap_or_else(|error| panic!("{error}"));
    bytes.into_inner()
}

fn processor(probability: f32) -> Result<PhotoProcessor<DeterministicSafetyFixture>, SafetyError> {
    PhotoProcessor::new(DeterministicSafetyFixture::new(probability)?, true)
}

struct InvalidScoreClassifier(f32);

impl PhotoSafetyClassifier for InvalidScoreClassifier {
    fn classify_rgb(&self, _width: u32, _height: u32, _rgb: &[u8]) -> Result<f32, SafetyError> {
        Ok(self.0)
    }

    fn mode(&self) -> ClassifierMode {
        ClassifierMode::Real
    }
}

#[test]
fn outgoing_reencodes_to_metadata_free_jpeg_and_hashes_normalized_bytes() {
    let result = processor(0.1).and_then(|validator| validator.prepare_outgoing(&jpeg(), 0.5));
    assert!(result.is_ok());
    if let Ok(photo) = result {
        assert_eq!(photo.media_type, "image/jpeg");
        assert_eq!(photo.content_hash, *blake3::hash(&photo.bytes).as_bytes());
        assert!(matches!(
            image::guess_format(&photo.bytes),
            Ok(ImageFormat::Jpeg)
        ));
    }
}

#[test]
fn incoming_checks_length_hash_decode_and_classifier_before_returning() {
    let photo = processor(0.1).and_then(|validator| validator.prepare_outgoing(&jpeg(), 0.5));
    let validated = photo.and_then(|photo| {
        processor(0.1)?.validate_incoming(&photo.bytes, photo.content_hash, photo.bytes.len(), 0.5)
    });
    assert!(validated.is_ok_and(|photo| photo.width == 8 && photo.height == 6));
    let wrong_length =
        processor(0.1).and_then(|validator| validator.validate_incoming(&jpeg(), [0; 32], 1, 0.5));
    assert_eq!(wrong_length, Err(SafetyError::LengthMismatch));
}

#[test]
fn invalid_scores_thresholds_and_fixture_opt_in_fail_closed() {
    assert_eq!(
        DeterministicSafetyFixture::new(f32::NAN).err(),
        Some(SafetyError::SafetyUnavailable)
    );
    assert_eq!(
        PhotoProcessor::new(DeterministicSafetyFixture { probability: 0.0 }, false).err(),
        Some(SafetyError::DevelopmentFixtureDisabled)
    );
    assert_eq!(
        processor(0.8).and_then(|validator| validator.prepare_outgoing(&jpeg(), 0.5)),
        Err(SafetyError::Rejected)
    );
    assert_eq!(
        processor(0.1).and_then(|validator| validator.prepare_outgoing(&jpeg(), f32::NAN)),
        Err(SafetyError::InvalidThreshold)
    );
}

#[test]
fn invalid_compressed_inputs_are_rejected() {
    assert_eq!(
        processor(0.1).and_then(|validator| validator.prepare_outgoing(b"bad", 0.5)),
        Err(SafetyError::UnsupportedFormat)
    );
    assert_eq!(
        processor(0.1).and_then(|validator| validator.prepare_outgoing(&[], 0.5)),
        Err(SafetyError::InvalidSize)
    );
}

#[test]
fn rejects_oversized_dimensions_and_compressed_payloads_before_classification() {
    let oversized = ImageBuffer::from_pixel(MAX_PHOTO_DIMENSION + 1, 1, Rgb([0, 0, 0]));
    let mut encoded = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(oversized)
        .write_to(&mut encoded, ImageFormat::Png)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        processor(0.0).and_then(|validator| validator.prepare_outgoing(&encoded.into_inner(), 1.0)),
        Err(SafetyError::InvalidImage)
    );
    let oversized_bytes = vec![0; MAX_PHOTO_BYTES + 1];
    assert_eq!(
        processor(0.0).and_then(|validator| validator.prepare_outgoing(&oversized_bytes, 1.0)),
        Err(SafetyError::InvalidSize)
    );
}

#[test]
fn rejects_hash_mismatch_and_invalid_classifier_scores() {
    let bytes = jpeg();
    let hash_mismatch = processor(0.0)
        .and_then(|validator| validator.validate_incoming(&bytes, [0; 32], bytes.len(), 1.0));
    assert_eq!(hash_mismatch, Err(SafetyError::HashMismatch));
    for score in [f32::NAN, f32::INFINITY, -0.1, 1.1] {
        let result = PhotoProcessor::new(InvalidScoreClassifier(score), false)
            .and_then(|validator| validator.prepare_outgoing(&bytes, 1.0));
        assert_eq!(result, Err(SafetyError::SafetyUnavailable));
    }
}

#[test]
fn moderation_records_are_bounded_and_unavailable_verification_fails_closed() {
    let report = ProfileReport {
        version: 1,
        report_id: [1; 16],
        reporter: [2; 32],
        subject: [3; 32],
        policy_reason: 1,
        evidence_hashes: vec![[4; 32]; MAX_REPORT_EVIDENCE_HASHES + 1],
        created_at: 10,
        signature: vec![5; 64],
    };
    assert_eq!(
        report.validate_bounds(),
        Err(ModerationError::InvalidReport)
    );

    let decision = ModerationDecision {
        version: 1,
        authority_id: [1; 32],
        authority_key: [2; 32],
        subject: [3; 32],
        policy_version: 1,
        reason_code: 1,
        issued_at: 10,
        expires_at: 20,
        signature: vec![4; 64],
    };
    assert_eq!(decision.validate_bounds(15), Ok(()));
    assert_eq!(
        UnavailableModerationVerifier.verify_decision(&decision, &[], 15),
        Err(ModerationError::VerifierUnavailable)
    );
    assert_eq!(
        decision.validate_bounds(20),
        Err(ModerationError::InvalidDecision)
    );
}
