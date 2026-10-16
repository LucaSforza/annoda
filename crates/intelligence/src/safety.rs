use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_PHOTO_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PHOTO_DIMENSION: u32 = 4_096;
const MAX_DECODED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PHOTO_PIXELS: u64 = 16_000_000;
pub const MAX_REPORT_EVIDENCE_HASHES: usize = 32;
pub const MAX_MODERATION_SIGNATURE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifierMode {
    Real,
    DevelopmentFixture,
}

pub trait PhotoSafetyClassifier: Send + Sync {
    fn classify_rgb(&self, width: u32, height: u32, rgb: &[u8]) -> Result<f32, SafetyError>;
    fn mode(&self) -> ClassifierMode;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SafetyError {
    #[error("photo is empty or exceeds the compressed size limit")]
    InvalidSize,
    #[error("only JPEG and PNG photos are supported")]
    UnsupportedFormat,
    #[error("photo dimensions exceed configured limits or the image is malformed")]
    InvalidImage,
    #[error("declared content length does not match photo bytes")]
    LengthMismatch,
    #[error("photo content hash does not match the declared hash")]
    HashMismatch,
    #[error("safety threshold must be finite and in [0, 1]")]
    InvalidThreshold,
    #[error("safety classifier is unavailable or returned an invalid score")]
    SafetyUnavailable,
    #[error("photo was rejected by the configured safety threshold")]
    Rejected,
    #[error("development fixture classifier requires explicit opt-in")]
    DevelopmentFixtureDisabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPhoto {
    pub bytes: Vec<u8>,
    pub content_hash: [u8; 32],
    pub media_type: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPhoto {
    pub bytes: Vec<u8>,
    pub content_hash: [u8; 32],
    pub media_type: &'static str,
    pub width: u32,
    pub height: u32,
}

pub struct PhotoProcessor<C> {
    classifier: C,
    allow_development_fixture: bool,
}

impl<C: PhotoSafetyClassifier> PhotoProcessor<C> {
    pub fn new(classifier: C, allow_development_fixture: bool) -> Result<Self, SafetyError> {
        if classifier.mode() == ClassifierMode::DevelopmentFixture && !allow_development_fixture {
            return Err(SafetyError::DevelopmentFixtureDisabled);
        }
        Ok(Self {
            classifier,
            allow_development_fixture,
        })
    }

    pub fn prepare_outgoing(
        &self,
        bytes: &[u8],
        threshold: f32,
    ) -> Result<NormalizedPhoto, SafetyError> {
        validate_threshold(threshold)?;
        let decoded = decode(bytes)?;

        // JPEG re-encoding removes source metadata; the signed content hash covers these bytes.
        let mut encoded = Cursor::new(Vec::new());
        decoded
            .image
            .write_to(&mut encoded, ImageFormat::Jpeg)
            .map_err(|_| SafetyError::InvalidImage)?;
        let normalized = encoded.into_inner();
        if normalized.len() > MAX_PHOTO_BYTES {
            return Err(SafetyError::InvalidSize);
        }
        // Classify the exact lossy-normalized pixels that are returned and later displayed.
        let normalized_image = decode(&normalized)?;
        self.classify(&normalized_image, threshold)?;
        Ok(NormalizedPhoto {
            content_hash: *blake3::hash(&normalized).as_bytes(),
            bytes: normalized,
            media_type: "image/jpeg",
        })
    }

    pub fn validate_incoming(
        &self,
        bytes: &[u8],
        expected_hash: [u8; 32],
        expected_len: usize,
        threshold: f32,
    ) -> Result<ValidatedPhoto, SafetyError> {
        validate_threshold(threshold)?;
        if bytes.len() != expected_len {
            return Err(SafetyError::LengthMismatch);
        }
        if bytes.is_empty() || bytes.len() > MAX_PHOTO_BYTES {
            return Err(SafetyError::InvalidSize);
        }
        if blake3::hash(bytes).as_bytes() != &expected_hash {
            return Err(SafetyError::HashMismatch);
        }
        let decoded = decode(bytes)?;
        self.classify(&decoded, threshold)?;
        Ok(ValidatedPhoto {
            bytes: bytes.to_vec(),
            content_hash: expected_hash,
            media_type: decoded.media_type,
            width: decoded.image.width(),
            height: decoded.image.height(),
        })
    }

    fn classify(&self, decoded: &DecodedPhoto, threshold: f32) -> Result<(), SafetyError> {
        if self.classifier.mode() == ClassifierMode::DevelopmentFixture
            && !self.allow_development_fixture
        {
            return Err(SafetyError::DevelopmentFixtureDisabled);
        }
        let pixels = decoded.image.to_rgb8();
        let probability = self
            .classifier
            .classify_rgb(pixels.width(), pixels.height(), pixels.as_raw())
            .map_err(|_| SafetyError::SafetyUnavailable)?;
        if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
            return Err(SafetyError::SafetyUnavailable);
        }
        if probability > threshold {
            return Err(SafetyError::Rejected);
        }
        Ok(())
    }
}

struct DecodedPhoto {
    image: DynamicImage,
    media_type: &'static str,
}

fn validate_threshold(threshold: f32) -> Result<(), SafetyError> {
    if threshold.is_finite() && (0.0..=1.0).contains(&threshold) {
        Ok(())
    } else {
        Err(SafetyError::InvalidThreshold)
    }
}

fn decode(bytes: &[u8]) -> Result<DecodedPhoto, SafetyError> {
    if bytes.is_empty() || bytes.len() > MAX_PHOTO_BYTES {
        return Err(SafetyError::InvalidSize);
    }
    let format = image::guess_format(bytes).map_err(|_| SafetyError::UnsupportedFormat)?;
    let media_type = match format {
        ImageFormat::Jpeg => "image/jpeg",
        ImageFormat::Png => "image/png",
        _ => return Err(SafetyError::UnsupportedFormat),
    };
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_PHOTO_DIMENSION);
    limits.max_image_height = Some(MAX_PHOTO_DIMENSION);
    limits.max_alloc = Some(MAX_DECODED_BYTES);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| SafetyError::InvalidImage)?;
    if image.width() == 0
        || image.height() == 0
        || image.width() > MAX_PHOTO_DIMENSION
        || image.height() > MAX_PHOTO_DIMENSION
        || u64::from(image.width()) * u64::from(image.height()) > MAX_PHOTO_PIXELS
    {
        return Err(SafetyError::InvalidImage);
    }
    Ok(DecodedPhoto { image, media_type })
}

/// Deterministic test fixture; the configured score is not a real image classification.
#[derive(Debug, Clone, Copy)]
pub struct DeterministicSafetyFixture {
    probability: f32,
}

impl DeterministicSafetyFixture {
    pub fn new(probability: f32) -> Result<Self, SafetyError> {
        if probability.is_finite() && (0.0..=1.0).contains(&probability) {
            Ok(Self { probability })
        } else {
            Err(SafetyError::SafetyUnavailable)
        }
    }
}

impl PhotoSafetyClassifier for DeterministicSafetyFixture {
    fn classify_rgb(&self, _width: u32, _height: u32, _rgb: &[u8]) -> Result<f32, SafetyError> {
        Ok(self.probability)
    }

    fn mode(&self) -> ClassifierMode {
        ClassifierMode::DevelopmentFixture
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileReport {
    pub version: u16,
    pub report_id: [u8; 16],
    pub reporter: [u8; 32],
    pub subject: [u8; 32],
    pub policy_reason: u16,
    pub evidence_hashes: Vec<[u8; 32]>,
    pub created_at: u64,
    pub signature: Vec<u8>,
}

impl ProfileReport {
    pub fn validate_bounds(&self) -> Result<(), ModerationError> {
        if self.version != 1
            || self.report_id == [0; 16]
            || self.reporter == [0; 32]
            || self.subject == [0; 32]
            || self.reporter == self.subject
            || self.policy_reason == 0
            || self.created_at == 0
            || self.evidence_hashes.is_empty()
            || self.evidence_hashes.len() > MAX_REPORT_EVIDENCE_HASHES
            || self.signature.is_empty()
            || self.signature.len() > MAX_MODERATION_SIGNATURE_BYTES
        {
            return Err(ModerationError::InvalidReport);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationDecision {
    pub version: u16,
    pub authority_id: [u8; 32],
    pub authority_key: [u8; 32],
    pub subject: [u8; 32],
    pub policy_version: u16,
    pub reason_code: u16,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

impl ModerationDecision {
    pub fn validate_bounds(&self, now: u64) -> Result<(), ModerationError> {
        if self.version != 1
            || self.authority_id == [0; 32]
            || self.authority_key == [0; 32]
            || self.subject == [0; 32]
            || self.policy_version == 0
            || self.reason_code == 0
            || self.issued_at == 0
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.signature.is_empty()
            || self.signature.len() > MAX_MODERATION_SIGNATURE_BYTES
        {
            return Err(ModerationError::InvalidDecision);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModerationAuthorityKey {
    pub authority_id: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModerationError {
    #[error("profile report is malformed or exceeds bounds")]
    InvalidReport,
    #[error("moderation decision is malformed or expired")]
    InvalidDecision,
    #[error("moderation authority is not trusted")]
    UntrustedAuthority,
    #[error("moderation verifier is unavailable")]
    VerifierUnavailable,
}

/// Verification trust is supplied by the moderation policy, independently of identity issuers.
pub trait ModerationDecisionVerifier: Send + Sync {
    fn verify_report(&self, report: &ProfileReport) -> Result<(), ModerationError>;

    fn verify_decision(
        &self,
        decision: &ModerationDecision,
        trusted_authorities: &[ModerationAuthorityKey],
        now: u64,
    ) -> Result<(), ModerationError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableModerationVerifier;

impl ModerationDecisionVerifier for UnavailableModerationVerifier {
    fn verify_report(&self, report: &ProfileReport) -> Result<(), ModerationError> {
        report.validate_bounds()?;
        Err(ModerationError::VerifierUnavailable)
    }

    fn verify_decision(
        &self,
        decision: &ModerationDecision,
        _trusted_authorities: &[ModerationAuthorityKey],
        now: u64,
    ) -> Result<(), ModerationError> {
        decision.validate_bounds(now)?;
        Err(ModerationError::VerifierUnavailable)
    }
}

#[cfg(test)]
#[path = "tests/safety.rs"]
mod tests;
