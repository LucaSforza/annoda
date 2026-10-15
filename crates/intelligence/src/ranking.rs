use std::collections::{HashSet, VecDeque};

use thiserror::Error;

const MAX_LEARNING_RATE: f64 = 1.0;
const MAX_EMBEDDING_VALUE: f64 = 1.0;

#[derive(Debug, Clone, PartialEq)]
pub struct PhotoEmbedding {
    pub version: u16,
    pub values: Vec<f64>,
}

impl PhotoEmbedding {
    pub fn new(version: u16, values: Vec<f64>) -> Result<Self, RankingError> {
        if values.is_empty() {
            return Err(RankingError::InvalidEmbedding);
        }
        if values
            .iter()
            .any(|value| !value.is_finite() || value.abs() > MAX_EMBEDDING_VALUE)
        {
            return Err(RankingError::InvalidEmbedding);
        }
        Ok(Self { version, values })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankingCandidate {
    pub id: String,
    pub verified_age: u8,
    pub adult_credential_valid: bool,
    pub coarse_region: Option<String>,
    pub embedding: PhotoEmbedding,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RankingScore {
    pub probability: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwipeFeedback {
    pub candidate_id: String,
    pub liked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFilter {
    pub minimum_age: u8,
    pub maximum_age: u8,
    pub coarse_region: Option<String>,
    pub blocked: HashSet<String>,
    pub passed: HashSet<String>,
    pub seen: HashSet<String>,
}

impl CandidateFilter {
    pub fn allows(&self, candidate: &RankingCandidate) -> bool {
        candidate.adult_credential_valid
            && (18..=u8::MAX).contains(&candidate.verified_age)
            && (self.minimum_age..=self.maximum_age).contains(&candidate.verified_age)
            && self
                .coarse_region
                .as_ref()
                .is_none_or(|region| candidate.coarse_region.as_ref() == Some(region))
            && !self.blocked.contains(&candidate.id)
            && !self.passed.contains(&candidate.id)
            && !self.seen.contains(&candidate.id)
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum RankingError {
    #[error("embedding is empty or contains an out-of-range or non-finite value")]
    InvalidEmbedding,
    #[error("embedding dimension or encoder version does not match the model")]
    IncompatibleEmbedding,
    #[error("learning rate or regularization is invalid")]
    InvalidTrainingConfig,
    #[error("exploration fraction must be finite and between zero and one")]
    InvalidExploration,
    #[error("training update could not produce finite model weights")]
    NumericalFailure,
}

#[derive(Debug, Clone)]
pub struct PreferenceModel {
    weights: Vec<f64>,
    bias: f64,
    learning_rate: f64,
    regularization: f64,
    encoder_version: u16,
    recent_seen: VecDeque<String>,
    recent_seen_limit: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankedCandidate {
    pub candidate_id: String,
    pub score: RankingScore,
    pub explored: bool,
}

impl PreferenceModel {
    pub fn new(
        dimensions: usize,
        encoder_version: u16,
        learning_rate: f64,
        regularization: f64,
        recent_seen_limit: usize,
    ) -> Result<Self, RankingError> {
        if dimensions == 0
            || !learning_rate.is_finite()
            || learning_rate <= 0.0
            || learning_rate > MAX_LEARNING_RATE
            || !regularization.is_finite()
            || regularization < 0.0
            || regularization > 1.0
        {
            return Err(RankingError::InvalidTrainingConfig);
        }
        Ok(Self {
            weights: vec![0.0; dimensions],
            bias: 0.0,
            learning_rate,
            regularization,
            encoder_version,
            recent_seen: VecDeque::new(),
            recent_seen_limit,
        })
    }

    pub fn score(&self, embedding: &PhotoEmbedding) -> Result<RankingScore, RankingError> {
        self.validate_embedding(embedding)?;
        let logit = self
            .weights
            .iter()
            .zip(&embedding.values)
            .fold(self.bias, |sum, (weight, value)| sum + weight * value);
        if !logit.is_finite() {
            return Err(RankingError::NumericalFailure);
        }
        Ok(RankingScore {
            probability: sigmoid(logit),
        })
    }

    pub fn update(&mut self, embedding: &PhotoEmbedding, liked: bool) -> Result<(), RankingError> {
        self.validate_embedding(embedding)?;
        let probability = self.score(embedding)?.probability;
        let target = f64::from(liked);
        let error = probability - target;
        let weights: Vec<_> = self
            .weights
            .iter()
            .zip(&embedding.values)
            .map(|(weight, value)| {
                weight - self.learning_rate * (error * value + self.regularization * weight)
            })
            .collect();
        let bias = self.bias - self.learning_rate * error;
        if !bias.is_finite() || weights.iter().any(|weight| !weight.is_finite()) {
            return Err(RankingError::NumericalFailure);
        }
        self.weights = weights;
        self.bias = bias;
        Ok(())
    }

    pub fn rank(
        &self,
        candidates: &[RankingCandidate],
        filter: &CandidateFilter,
        exploration_fraction: f64,
        seed: u64,
    ) -> Result<Vec<RankedCandidate>, RankingError> {
        if !exploration_fraction.is_finite() || !(0.0..=1.0).contains(&exploration_fraction) {
            return Err(RankingError::InvalidExploration);
        }
        let recent_seen: HashSet<&str> = self.recent_seen.iter().map(String::as_str).collect();
        let mut candidate_ids = HashSet::new();
        let mut ranked = candidates
            .iter()
            .filter(|candidate| {
                filter.allows(candidate)
                    && !recent_seen.contains(candidate.id.as_str())
                    && candidate_ids.insert(candidate.id.as_str())
            })
            .map(|candidate| {
                Ok((
                    candidate.id.as_str(),
                    self.score(&candidate.embedding)?.probability,
                ))
            })
            .collect::<Result<Vec<_>, RankingError>>()?;
        ranked.sort_by(|left, right| right.1.total_cmp(&left.1).then_with(|| left.0.cmp(right.0)));

        // The seed controls which eligible candidates enter the exploratory prefix.
        let explore_count = ((ranked.len() as f64) * exploration_fraction).floor() as usize;
        let mut random = SplitMix64(seed);
        let mut shuffled = ranked.clone();
        for index in (1..shuffled.len()).rev() {
            let swap = (random.next() as usize) % (index + 1);
            shuffled.swap(index, swap);
        }
        let exploratory = shuffled[..explore_count].to_vec();
        let exploratory_ids: HashSet<_> = exploratory.iter().map(|(id, _)| *id).collect();
        ranked.retain(|(id, _)| !exploratory_ids.contains(id));
        let mut output = exploratory
            .into_iter()
            .map(|(id, probability)| RankedCandidate {
                candidate_id: id.to_owned(),
                score: RankingScore { probability },
                explored: true,
            })
            .collect::<Vec<_>>();
        output.extend(ranked.into_iter().map(|(id, probability)| RankedCandidate {
            candidate_id: id.to_owned(),
            score: RankingScore { probability },
            explored: false,
        }));
        Ok(output)
    }

    pub fn record_seen(&mut self, candidate_id: String) {
        if self.recent_seen_limit == 0 {
            return;
        }
        self.recent_seen.retain(|id| id != &candidate_id);
        self.recent_seen.push_back(candidate_id);
        while self.recent_seen.len() > self.recent_seen_limit {
            self.recent_seen.pop_front();
        }
    }

    pub fn recent_seen(&self) -> HashSet<String> {
        self.recent_seen.iter().cloned().collect()
    }

    pub fn reset(&mut self) {
        self.weights.fill(0.0);
        self.bias = 0.0;
        self.recent_seen.clear();
    }

    pub fn footprint_bytes(&self) -> usize {
        self.weights.capacity() * std::mem::size_of::<f64>()
            + self.recent_seen.capacity() * std::mem::size_of::<String>()
            + self.recent_seen.iter().map(String::capacity).sum::<usize>()
            + std::mem::size_of::<f64>()
    }

    fn validate_embedding(&self, embedding: &PhotoEmbedding) -> Result<(), RankingError> {
        if embedding.version != self.encoder_version || embedding.values.len() != self.weights.len()
        {
            return Err(RankingError::IncompatibleEmbedding);
        }
        if embedding
            .values
            .iter()
            .any(|value| !value.is_finite() || value.abs() > MAX_EMBEDDING_VALUE)
        {
            return Err(RankingError::InvalidEmbedding);
        }
        Ok(())
    }
}

fn sigmoid(value: f64) -> f64 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exponential = value.exp();
        exponential / (1.0 + exponential)
    }
}

#[derive(Debug, Clone, Copy)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }
}

pub trait PhotoEncoder {
    fn encode(&self, photo: &[u8]) -> Result<PhotoEmbedding, RankingError>;
    fn description(&self) -> &'static str;
}

/// Byte-shape fixture for tests and simulations; it does not infer visual preferences.
#[derive(Debug, Clone, Copy)]
pub struct DeterministicPhotoEncoder {
    dimensions: usize,
    version: u16,
}

impl DeterministicPhotoEncoder {
    pub fn development_fixture(dimensions: usize, version: u16) -> Result<Self, RankingError> {
        if dimensions == 0 {
            return Err(RankingError::InvalidEmbedding);
        }
        Ok(Self {
            dimensions,
            version,
        })
    }
}

impl PhotoEncoder for DeterministicPhotoEncoder {
    fn encode(&self, photo: &[u8]) -> Result<PhotoEmbedding, RankingError> {
        if photo.is_empty() {
            return Err(RankingError::InvalidEmbedding);
        }
        let mut buckets = vec![0.0; self.dimensions];
        for (index, byte) in photo.iter().enumerate() {
            buckets[index % self.dimensions] += f64::from(*byte) / 255.0;
        }
        let scale = photo.len().div_ceil(self.dimensions).max(1) as f64;
        for bucket in &mut buckets {
            *bucket = (*bucket / scale).clamp(0.0, 1.0);
        }
        PhotoEmbedding::new(self.version, buckets)
    }

    fn description(&self) -> &'static str {
        "development fixture; byte-shape features only, not visual preference inference"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn embedding(values: &[f64]) -> PhotoEmbedding {
        PhotoEmbedding::new(1, values.to_vec()).unwrap_or_else(|error| panic!("{error}"))
    }

    fn model() -> PreferenceModel {
        PreferenceModel::new(2, 1, 0.2, 0.01, 3).unwrap_or_else(|error| panic!("{error}"))
    }

    fn candidate(id: &str, age: u8, region: Option<&str>) -> RankingCandidate {
        RankingCandidate {
            id: id.to_owned(),
            verified_age: age,
            adult_credential_valid: true,
            coarse_region: region.map(str::to_owned),
            embedding: embedding(&[0.2, 0.8]),
        }
    }

    fn filter() -> CandidateFilter {
        CandidateFilter {
            minimum_age: 18,
            maximum_age: 90,
            coarse_region: None,
            blocked: HashSet::new(),
            passed: HashSet::new(),
            seen: HashSet::new(),
        }
    }

    #[test]
    fn stable_sigmoid_and_feedback_move_score_in_expected_direction() {
        let mut initial_model = model();
        let item = embedding(&[0.5, 0.5]);
        let before = initial_model.score(&item).map(|score| score.probability);
        assert_eq!(before, Ok(0.5));
        assert!(initial_model.update(&item, true).is_ok());
        assert!(
            initial_model
                .score(&item)
                .is_ok_and(|score| score.probability > 0.5)
        );

        let mut extreme = model();
        extreme.weights[0] = 1_000.0;
        let high = PhotoEmbedding::new(1, vec![1.0, 0.0]);
        let low = PhotoEmbedding::new(1, vec![-1.0, 0.0]);
        assert!(high.is_ok_and(|value| extreme.score(&value).is_ok_and(|s| s.probability == 1.0)));
        assert!(low.is_ok_and(|value| {
            extreme
                .score(&value)
                .is_ok_and(|s| s.probability.is_finite())
        }));
        extreme.weights[1] = f64::INFINITY;
        assert_eq!(
            extreme.score(&embedding(&[1.0, 1.0])),
            Err(RankingError::NumericalFailure)
        );
    }

    #[test]
    fn filters_hard_bounds_unknown_region_and_recent_seen() {
        let mut constraints = filter();
        constraints.coarse_region = Some("north".into());
        let mut model = model();
        model.record_seen("seen".into());
        let candidates = vec![
            candidate("valid", 20, Some("north")),
            candidate("unknown", 20, None),
            candidate("minor", 17, Some("north")),
            candidate("seen", 25, Some("north")),
        ];
        let ranked = model.rank(&candidates, &constraints, 0.0, 1);
        assert_eq!(
            ranked.map(|items| items
                .into_iter()
                .map(|x| x.candidate_id)
                .collect::<Vec<_>>()),
            Ok(vec!["valid".into()])
        );
    }

    #[test]
    fn seeded_exploration_is_repeatable_and_reset_clears_learning_and_history() {
        let candidates = vec![
            candidate("a", 20, None),
            candidate("b", 21, None),
            candidate("c", 22, None),
        ];
        let mut model = model();
        let first = model.rank(&candidates, &filter(), 0.67, 42);
        let second = model.rank(&candidates, &filter(), 0.67, 42);
        assert_eq!(first, second);
        assert!(first.is_ok_and(|items| items.iter().filter(|item| item.explored).count() == 2));
        model.record_seen("a".into());
        assert!(
            model
                .rank(&[candidate("a", 20, None)], &filter(), 0.0, 42)
                .is_ok_and(|items| items.is_empty())
        );
        assert!(model.update(&embedding(&[0.9, 0.1]), true).is_ok());
        model.reset();
        assert!(model.recent_seen().is_empty());
        assert_eq!(
            model
                .score(&embedding(&[0.9, 0.1]))
                .map(|score| score.probability),
            Ok(0.5)
        );
    }

    #[test]
    fn duplicate_ids_do_not_change_exploration_coverage() {
        let candidates = vec![
            candidate("same", 20, None),
            candidate("same", 20, None),
            candidate("other", 21, None),
        ];
        let ranked = model().rank(&candidates, &filter(), 1.0, 9);
        assert_eq!(ranked.map(|items| items.len()), Ok(2));
    }

    #[test]
    fn rejects_invalid_dimensions_ranges_and_non_finite_feedback() {
        let mut model = model();
        let invalid_value = PhotoEmbedding {
            version: 1,
            values: vec![f64::NAN, 0.1],
        };
        assert_eq!(
            model.score(&invalid_value),
            Err(RankingError::InvalidEmbedding)
        );
        assert_eq!(
            model.score(&embedding(&[0.1])),
            Err(RankingError::IncompatibleEmbedding)
        );
        assert_eq!(model.update(&embedding(&[0.1, 0.2]), false), Ok(()));
        assert_eq!(
            model.score(&PhotoEmbedding {
                version: 2,
                values: vec![0.0, 0.0]
            }),
            Err(RankingError::IncompatibleEmbedding)
        );
        assert_eq!(
            model.rank(&[], &filter(), f64::NAN, 0),
            Err(RankingError::InvalidExploration)
        );
        assert_eq!(
            PreferenceModel::new(2, 1, 1.0, f64::MAX, 3).err(),
            Some(RankingError::InvalidTrainingConfig)
        );
    }

    proptest! {
        #[test]
        fn scores_are_finite_and_bounded_for_all_valid_embeddings(values in prop::collection::vec(-1.0f64..=1.0, 1..32)) {
            let Ok(embedding) = PhotoEmbedding::new(1, values.clone()) else { return Ok(()) };
            let Ok(model) = PreferenceModel::new(values.len(), 1, 0.5, 0.1, 5) else { return Ok(()) };
            let score = model.score(&embedding);
            prop_assert!(score.is_ok_and(|value| value.probability.is_finite() && (0.0..=1.0).contains(&value.probability)));
        }

        #[test]
        fn feedback_sequences_keep_scores_finite(updates in prop::collection::vec(
            (-1.0f64..=1.0, -1.0f64..=1.0, -1.0f64..=1.0, -1.0f64..=1.0, any::<bool>()),
            0..128
        )) {
            let Ok(mut model) = PreferenceModel::new(4, 1, 0.5, 0.5, 5) else { return Ok(()) };
            for (a, b, c, d, liked) in updates {
                let Ok(embedding) = PhotoEmbedding::new(1, vec![a, b, c, d]) else { return Ok(()) };
                prop_assert!(model.update(&embedding, liked).is_ok());
                let score = model.score(&embedding);
                prop_assert!(score.is_ok_and(|value| value.probability.is_finite() && (0.0..=1.0).contains(&value.probability)));
            }
            let wrong_version = PhotoEmbedding { version: 2, values: vec![0.0; 4] };
            let wrong_dimension = PhotoEmbedding { version: 1, values: vec![0.0; 3] };
            prop_assert!(model.score(&wrong_version).is_err());
            prop_assert!(model.score(&wrong_dimension).is_err());
        }
    }
}
