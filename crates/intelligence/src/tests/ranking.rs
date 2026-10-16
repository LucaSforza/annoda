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
