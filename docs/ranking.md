# Local ranking and evaluation

For finite fixed-size photo embedding z, score p = sigmoid(w·z+b), implemented stably for large positive/negative logits. Online logistic-loss SGD: w ← w − η((p−y)z + λw), b ← b − η(p−y), y=1 for like, 0 for pass. Require 0 < learning rate ≤ 1 and 0 ≤ regularization ≤ 1; reject a training update atomically if any resulting weight or bias is nonfinite; vectors must match dimensions and contain only finite values. Normalize or bound embeddings before use. Model and feedback never leave device.

Cold start uses zero weights/bias and deterministic seeded exploration; ties break by stable candidate identifier. CandidateFilter applies credential/adult validity, explicit user age range, blocked/passed/seen exclusions and user-selected coarse region before scoring. No sensitive attribute inference from photos. Coarse location is user-provided, never precise GPS. Unknown geography must have explicit behavior rather than silently passing a requested hard bound.

Use configurable exploration fraction to expose new users and avoid repetition; retain bounded recent-seen local history. Reset deletes model and training history. Received-like inbox uses identical model/filter rules but reveals received likes independently of ranking and never requires sender access to recipient model. Single fixed seed is for tests only.

PhotoEncoder returns embedding dimension/version and finite feature vectors. Deterministic simulation encoder is not visual preference intelligence; real mobile encoder is planned. Version changes reset/retrain incompatible weights. Benchmark CPU time and storage per candidate batch; model footprint O(d), scoring O(nd), update O(d). Mobile inference depends on chosen model, must be benchmarked on devices before numerical claims.

Metrics on synthetic labels only: Precision@K = relevant top K / min(K, returned count), Recall@K = relevant top K / all relevant ground truth, NDCG@K = DCG / ideal DCG with gain 2^rel−1 and discount log2(i+2). Empty denominators return documented zero. Also measure mutual-positive rate, unique candidate coverage, exposure histogram/distribution, cold-start metrics, elapsed CPU/wall time and approximate memory. Report sample size, seed, eligibility policy and missing ground truth. Synthetic predictions are never real-world dating performance.

[Ranking classes](uml/classes.md). [Testing](testing.md) defines deterministic requirements.

The synthetic evaluator macro-averages Precision/Recall/NDCG over samples with ground truth. Coverage, exposure histogram and mutual-positive rate use all supplied unique ranked candidates, independently of K; caller can truncate input to evaluate an exposure budget. Unknown labels are counted and excluded from label averages. CPU/wall measurements come from the host process, approximate memory from owned records, not mobile-device benchmarks.
