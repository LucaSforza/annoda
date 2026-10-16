use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use annoda_intelligence::ranking::{EncoderMode, PhotoEmbedding, PhotoEncoder, RankingError};

use super::encode_photo_if_allowed;

struct RenamedFixture(Arc<AtomicUsize>);

impl PhotoEncoder for RenamedFixture {
    fn encode(&self, _photo: &[u8]) -> Result<PhotoEmbedding, RankingError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        PhotoEmbedding::new(1, vec![0.5])
    }

    fn description(&self) -> &'static str {
        "fixture implementation with a renamed description"
    }

    fn mode(&self) -> EncoderMode {
        EncoderMode::DevelopmentFixture
    }
}

#[test]
fn renamed_development_encoder_is_not_run_without_explicit_opt_in() {
    let calls = Arc::new(AtomicUsize::new(0));
    let encoder = RenamedFixture(Arc::clone(&calls));
    let result = encode_photo_if_allowed(&encoder, b"validated image", false)
        .expect("fixture policy should not be an error");

    assert!(result.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn renamed_development_encoder_runs_after_explicit_opt_in() {
    let calls = Arc::new(AtomicUsize::new(0));
    let encoder = RenamedFixture(Arc::clone(&calls));
    let result = encode_photo_if_allowed(&encoder, b"validated image", true)
        .expect("explicitly opted-in fixture should encode");

    assert!(result.is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
