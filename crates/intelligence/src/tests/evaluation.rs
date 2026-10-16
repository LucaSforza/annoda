use super::*;

#[test]
fn computes_label_metrics_coverage_mutual_rate_and_zero_exposure() {
    let pool: HashSet<_> = ["a", "b", "c"].into_iter().map(str::to_owned).collect();
    let samples = vec![
        EvaluationSample {
            ranked_ids: vec!["a".into(), "b".into()],
            relevant_ids: Some(["a".to_owned()].into()),
            mutual_positive_ids: ["a".to_owned()].into(),
        },
        EvaluationSample {
            ranked_ids: vec!["b".into()],
            relevant_ids: None,
            mutual_positive_ids: HashSet::new(),
        },
    ];
    let metrics = evaluate(&samples, &pool, 1);
    assert_eq!(metrics.sample_size, 2);
    assert_eq!(metrics.samples_with_ground_truth, 1);
    assert_eq!(metrics.missing_ground_truth_samples, 1);
    assert_eq!(metrics.precision_at_k, 1.0);
    assert_eq!(metrics.recall_at_k, 1.0);
    assert_eq!(metrics.ndcg_at_k, 1.0);
    assert_eq!(metrics.mutual_positive_rate, 1.0 / 3.0);
    assert_eq!(metrics.unique_candidate_coverage, 2.0 / 3.0);
    assert_eq!(metrics.exposure_histogram, [(0, 1), (1, 1), (2, 1)].into());
}

#[test]
fn empty_inputs_and_zero_k_have_documented_zero_metrics() {
    let empty = evaluate(&[], &HashSet::new(), 0);
    assert_eq!(empty.precision_at_k, 0.0);
    assert_eq!(empty.recall_at_k, 0.0);
    assert_eq!(empty.ndcg_at_k, 0.0);
    assert_eq!(empty.unique_candidate_coverage, 0.0);
    let sample = EvaluationSample {
        ranked_ids: vec!["a".into()],
        relevant_ids: Some(["a".to_owned()].into()),
        mutual_positive_ids: HashSet::new(),
    };
    let metrics = evaluate(&[sample], &HashSet::from(["a".to_owned()]), 0);
    assert_eq!(metrics.precision_at_k, 0.0);
    assert_eq!(metrics.recall_at_k, 0.0);
    assert_eq!(metrics.ndcg_at_k, 0.0);
}

#[test]
fn duplicate_ids_are_counted_once_and_out_of_pool_ids_stay_recommendations() {
    let pool = HashSet::from(["a".to_owned()]);
    let sample = EvaluationSample {
        ranked_ids: vec!["outside".into(), "a".into(), "a".into()],
        relevant_ids: Some(HashSet::from(["a".to_owned()])),
        mutual_positive_ids: HashSet::from(["a".to_owned()]),
    };

    let metrics = evaluate(&[sample], &pool, 2);
    assert_eq!(metrics.precision_at_k, 0.5);
    assert_eq!(metrics.recall_at_k, 1.0);
    assert_eq!(metrics.ndcg_at_k, 1.0 / 3.0_f64.log2());
    assert_eq!(metrics.mutual_positive_rate, 0.5);
    assert_eq!(metrics.unique_candidate_coverage, 1.0);
    assert_eq!(metrics.exposure_histogram, [(1, 1)].into());
}
