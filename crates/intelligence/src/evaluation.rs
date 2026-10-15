use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationSample {
    pub ranked_ids: Vec<String>,
    /// None means this sample has no synthetic ground truth and is excluded from label metrics.
    pub relevant_ids: Option<HashSet<String>>,
    pub mutual_positive_ids: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankingMetrics {
    pub sample_size: usize,
    pub samples_with_ground_truth: usize,
    pub missing_ground_truth_samples: usize,
    pub candidate_pool_size: usize,
    pub k: usize,
    pub precision_at_k: f64,
    pub recall_at_k: f64,
    pub ndcg_at_k: f64,
    pub mutual_positive_rate: f64,
    pub unique_candidate_coverage: f64,
    /// Maps exposure count to number of candidates with that count, including zero exposure.
    pub exposure_histogram: BTreeMap<usize, usize>,
}

pub fn evaluate(
    samples: &[EvaluationSample],
    candidate_pool: &HashSet<String>,
    k: usize,
) -> RankingMetrics {
    let mut precision_sum = 0.0;
    let mut recall_sum = 0.0;
    let mut ndcg_sum = 0.0;
    let mut known_samples = 0usize;
    let mut total_recommendations = 0usize;
    let mut mutual_recommendations = 0usize;
    let mut exposed_ids = HashSet::new();
    let mut exposure_counts: BTreeMap<String, usize> =
        candidate_pool.iter().cloned().map(|id| (id, 0)).collect();

    for sample in samples {
        // Keep the first occurrence: repeated IDs cannot improve ranking metrics or inflate
        // mutual-positive exposure. IDs outside the pool remain valid recommendations, but
        // only pool members contribute to pool coverage and its exposure histogram.
        let mut seen = HashSet::new();
        let ranked_ids: Vec<_> = sample
            .ranked_ids
            .iter()
            .filter(|id| seen.insert(id.as_str()))
            .collect();

        for id in &ranked_ids {
            total_recommendations += 1;
            if sample.mutual_positive_ids.contains(*id) {
                mutual_recommendations += 1;
            }
            exposed_ids.insert((*id).clone());
            if let Some(count) = exposure_counts.get_mut(*id) {
                *count += 1;
            }
        }

        let Some(relevant) = sample.relevant_ids.as_ref() else {
            continue;
        };
        known_samples += 1;
        if k == 0 {
            continue;
        }
        let top_k: Vec<_> = ranked_ids.iter().take(k).collect();
        let hits = top_k
            .iter()
            .filter(|id| relevant.contains(id.as_str()))
            .count();
        let precision_denominator = k.min(ranked_ids.len());
        if precision_denominator > 0 {
            precision_sum += hits as f64 / precision_denominator as f64;
        }
        if !relevant.is_empty() {
            recall_sum += hits as f64 / relevant.len() as f64;
        }

        let dcg = top_k
            .iter()
            .enumerate()
            .filter(|(_, id)| relevant.contains(id.as_str()))
            .map(|(rank, _)| 1.0 / ((rank + 2) as f64).log2())
            .sum::<f64>();
        let ideal_hits = relevant.len().min(k);
        let ideal_dcg = (0..ideal_hits)
            .map(|rank| 1.0 / ((rank + 2) as f64).log2())
            .sum::<f64>();
        if ideal_dcg > 0.0 {
            ndcg_sum += dcg / ideal_dcg;
        }
    }

    let mut exposure_histogram = BTreeMap::new();
    for count in exposure_counts.into_values() {
        *exposure_histogram.entry(count).or_insert(0) += 1;
    }
    let denominator = known_samples.max(1) as f64;
    RankingMetrics {
        sample_size: samples.len(),
        samples_with_ground_truth: known_samples,
        missing_ground_truth_samples: samples.len() - known_samples,
        candidate_pool_size: candidate_pool.len(),
        k,
        precision_at_k: precision_sum / denominator,
        recall_at_k: recall_sum / denominator,
        ndcg_at_k: ndcg_sum / denominator,
        mutual_positive_rate: if total_recommendations == 0 {
            0.0
        } else {
            mutual_recommendations as f64 / total_recommendations as f64
        },
        unique_candidate_coverage: if candidate_pool.is_empty() {
            0.0
        } else {
            exposed_ids.intersection(candidate_pool).count() as f64 / candidate_pool.len() as f64
        },
        exposure_histogram,
    }
}

#[cfg(test)]
mod tests {
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
}
