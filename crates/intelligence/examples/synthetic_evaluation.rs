use std::{collections::HashSet, mem::size_of, time::Instant};

use annoda_intelligence::{
    evaluation::{EvaluationSample, RankingMetrics, evaluate},
    ranking::{CandidateFilter, PhotoEmbedding, PreferenceModel, RankingCandidate},
};
use cpu_time::ProcessTime;

const SEED: u64 = 2_026;
const K: usize = 5;
const USERS: [[f64; 2]; 4] = [[1.0, 1.0], [1.0, -1.0], [-1.0, 1.0], [-1.0, -1.0]];
const TRAINING_INDICES: [usize; 4] = [0, 3, 12, 15];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let candidates = synthetic_candidates()?;
    let pool: HashSet<_> = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let eligibility_policy =
        "valid adult credential; age 18-60; coarse region north; block/pass/seen excluded";
    let cpu_start = ProcessTime::try_now().ok();
    let wall_start = Instant::now();
    let mut cold_samples = Vec::new();
    let mut personalized_samples = Vec::new();
    let mut model_bytes = 0usize;

    for (user_index, preference) in USERS.iter().enumerate() {
        let mut model = PreferenceModel::new(2, 1, 0.25, 0.01, 8)?;
        let mut filter = CandidateFilter {
            minimum_age: 18,
            maximum_age: 60,
            coarse_region: Some("north".into()),
            blocked: HashSet::new(),
            passed: HashSet::new(),
            seen: HashSet::new(),
        };
        let relevant: HashSet<_> = candidates
            .iter()
            .filter(|candidate| is_relevant(preference, candidate))
            .map(|candidate| candidate.id.clone())
            .collect();
        let next_preference = USERS[(user_index + 1) % USERS.len()];
        let mutual: HashSet<_> = candidates
            .iter()
            .filter(|candidate| {
                is_relevant(preference, candidate) && is_relevant(&next_preference, candidate)
            })
            .map(|candidate| candidate.id.clone())
            .collect();

        let cold_ranked = model.rank(&candidates, &filter, 0.25, SEED + user_index as u64)?;
        cold_samples.push(EvaluationSample {
            ranked_ids: cold_ranked
                .into_iter()
                .map(|item| item.candidate_id)
                .collect(),
            relevant_ids: Some(relevant.clone()),
            mutual_positive_ids: mutual.clone(),
        });

        for index in TRAINING_INDICES {
            if let Some(candidate) = candidates.get(index) {
                let liked = relevant.contains(&candidate.id);
                model.update(&candidate.embedding, liked)?;
                model.record_seen(candidate.id.clone());
                filter.seen.insert(candidate.id.clone());
            }
        }
        let personalized_ranked =
            model.rank(&candidates, &filter, 0.25, SEED + 100 + user_index as u64)?;
        let unseen_relevant = relevant
            .difference(&filter.seen)
            .cloned()
            .collect::<HashSet<_>>();
        personalized_samples.push(EvaluationSample {
            ranked_ids: personalized_ranked
                .into_iter()
                .map(|item| item.candidate_id)
                .collect(),
            relevant_ids: Some(unseen_relevant),
            mutual_positive_ids: mutual,
        });
        model_bytes += model.footprint_bytes();
    }

    let wall_time = wall_start.elapsed();
    let cpu_time = cpu_start.and_then(|start| start.try_elapsed().ok());
    let cold = evaluate(&cold_samples, &pool, K);
    let personalized = evaluate(&personalized_samples, &pool, K);
    let candidate_bytes = candidates
        .iter()
        .map(|candidate| {
            size_of::<RankingCandidate>()
                + candidate.id.capacity()
                + candidate.embedding.values.capacity() * size_of::<f64>()
                + candidate.coarse_region.as_ref().map_or(0, String::capacity)
        })
        .sum::<usize>();

    println!("synthetic ranking evaluation (not real-world preference performance)");
    println!(
        "samples={} candidates={} seed={} k={K}",
        USERS.len(),
        pool.len(),
        SEED
    );
    println!("eligibility={eligibility_policy}");
    println!("missing_ground_truth_samples=0");
    print_metrics("cold_start", &cold);
    print_metrics("after_synthetic_feedback", &personalized);
    println!(
        "elapsed_wall_us={} process_cpu_us={}",
        wall_time.as_micros(),
        cpu_time.map_or_else(
            || "unavailable".to_owned(),
            |time| time.as_micros().to_string()
        )
    );
    println!("approx_model_bytes={model_bytes} approx_candidate_record_bytes={candidate_bytes}");
    Ok(())
}

fn synthetic_candidates() -> Result<Vec<RankingCandidate>, Box<dyn std::error::Error>> {
    let axis = [-1.0, -0.5, 0.5, 1.0];
    let mut candidates = Vec::with_capacity(axis.len() * axis.len());
    for (x_index, x) in axis.iter().enumerate() {
        for (y_index, y) in axis.iter().enumerate() {
            let index = x_index * axis.len() + y_index;
            candidates.push(RankingCandidate {
                id: format!("synthetic-{index:02}"),
                verified_age: 24 + (index % 12) as u8,
                adult_credential_valid: true,
                coarse_region: Some("north".to_owned()),
                embedding: PhotoEmbedding::new(1, vec![*x, *y])?,
            });
        }
    }
    Ok(candidates)
}

fn is_relevant(preference: &[f64; 2], candidate: &RankingCandidate) -> bool {
    preference
        .iter()
        .zip(&candidate.embedding.values)
        .map(|(left, right)| left * right)
        .sum::<f64>()
        > 0.0
}

fn print_metrics(label: &str, metrics: &RankingMetrics) {
    println!(
        "{label}: precision@{}={:.3} recall@{}={:.3} ndcg@{}={:.3} mutual_positive_rate={:.3} unique_coverage={:.3} exposure_histogram={:?}",
        metrics.k,
        metrics.precision_at_k,
        metrics.k,
        metrics.recall_at_k,
        metrics.k,
        metrics.ndcg_at_k,
        metrics.mutual_positive_rate,
        metrics.unique_candidate_coverage,
        metrics.exposure_histogram
    );
}
