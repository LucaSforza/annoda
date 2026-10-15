#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use annoda_intelligence::ranking::{PhotoEmbedding, PreferenceModel, RankingError};
use thiserror::Error;

uniffi::setup_scaffolding!();

const MAX_MODEL_DIMENSIONS: u32 = 4_096;

#[derive(Debug, Error, PartialEq, Eq, uniffi::Error)]
pub enum FfiError {
    #[error("input is invalid or exceeds supported bounds")]
    InvalidInput,
    #[error("the embedding does not match this model")]
    IncompatibleModel,
    #[error("the local preference model is unavailable")]
    Internal,
}

impl From<RankingError> for FfiError {
    fn from(error: RankingError) -> Self {
        match error {
            RankingError::IncompatibleEmbedding => Self::IncompatibleModel,
            RankingError::InvalidEmbedding
            | RankingError::InvalidTrainingConfig
            | RankingError::InvalidExploration => Self::InvalidInput,
            RankingError::NumericalFailure => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct FfiRankingScore {
    pub probability: f64,
}

#[derive(uniffi::Object)]
pub struct LocalPreferenceModel {
    model: Mutex<PreferenceModel>,
}

#[uniffi::export]
impl LocalPreferenceModel {
    #[uniffi::constructor]
    pub fn new(dimensions: u32, encoder_version: u16) -> Result<Arc<Self>, FfiError> {
        if dimensions == 0 || dimensions > MAX_MODEL_DIMENSIONS {
            return Err(FfiError::InvalidInput);
        }
        let model = PreferenceModel::new(dimensions as usize, encoder_version, 0.1, 0.001, 64)
            .map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            model: Mutex::new(model),
        }))
    }

    pub fn score(&self, version: u16, values: Vec<f64>) -> Result<FfiRankingScore, FfiError> {
        let embedding = PhotoEmbedding::new(version, values).map_err(FfiError::from)?;
        let model = self.model.lock().map_err(|_| FfiError::Internal)?;
        let score = model.score(&embedding).map_err(FfiError::from)?;
        Ok(FfiRankingScore {
            probability: score.probability,
        })
    }

    pub fn record_feedback(
        &self,
        version: u16,
        values: Vec<f64>,
        liked: bool,
    ) -> Result<(), FfiError> {
        let embedding = PhotoEmbedding::new(version, values).map_err(FfiError::from)?;
        self.model
            .lock()
            .map_err(|_| FfiError::Internal)?
            .update(&embedding, liked)
            .map_err(FfiError::from)
    }

    pub fn reset(&self) -> Result<(), FfiError> {
        self.model.lock().map_err(|_| FfiError::Internal)?.reset();
        Ok(())
    }
}

#[uniffi::export]
pub fn api_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_ranker_is_local_and_reports_typed_input_errors() {
        let ranker = LocalPreferenceModel::new(2, 7);
        assert!(ranker.is_ok());
        let Ok(ranker) = ranker else {
            return;
        };
        assert_eq!(
            ranker
                .score(7, vec![0.3, 0.4])
                .map(|score| score.probability),
            Ok(0.5)
        );
        assert_eq!(ranker.score(7, vec![0.3]), Err(FfiError::IncompatibleModel));
        assert_eq!(ranker.record_feedback(7, vec![0.3, 0.4], true), Ok(()));
        assert!(
            ranker
                .score(7, vec![0.3, 0.4])
                .is_ok_and(|score| score.probability > 0.5)
        );
        assert_eq!(ranker.reset(), Ok(()));
        assert_eq!(
            ranker
                .score(7, vec![0.3, 0.4])
                .map(|score| score.probability),
            Ok(0.5)
        );
    }

    #[test]
    fn constructor_bounds_model_allocation() {
        assert_eq!(
            LocalPreferenceModel::new(0, 1).err(),
            Some(FfiError::InvalidInput)
        );
        assert_eq!(
            LocalPreferenceModel::new(MAX_MODEL_DIMENSIONS + 1, 1).err(),
            Some(FfiError::InvalidInput)
        );
    }
}
