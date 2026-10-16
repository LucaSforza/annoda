## E. Ranking

```mermaid
classDiagram
    class PreferenceModel {
        -List weights
        -f64 bias
        +score(embedding) RankingScore
        +update(feedback) Result
        +reset() Result
    }
    class PhotoEmbedding {
        +u16 version
        +List values
    }
    class RankingCandidate {
        +ProfileId id
        +u8 verified_age
        +String coarse_region
    }
    class RankingScore {
        +f64 probability
    }
    class SwipeFeedback {
        +ProfileId candidate
        +bool liked
    }
    class CandidateFilter {
        +u8 minimum_age
        +u8 maximum_age
        +String coarse_region
        +allows(candidate) bool
    }
    class PhotoEncoder {
        <<interface>>
        +encode(photo) PhotoEmbedding
    }
    PreferenceModel "1" ..> "0..*" SwipeFeedback : learns locally
    PreferenceModel ..> RankingScore : produces
    RankingCandidate "1" *-- "1..*" PhotoEmbedding
    CandidateFilter ..> RankingCandidate : filters before scoring
    PhotoEncoder ..> PhotoEmbedding : creates
    PreferenceModel ..> PhotoEmbedding : fixed dimension
```

Mapping: intelligence::ranking structs PreferenceModel, PhotoEmbedding, RankingCandidate, RankingScore, SwipeFeedback, CandidateFilter and PhotoEncoder trait. Fields may be equivalent wrappers; no scores enter protocol. Invariants: finite vectors, fixed encoder version/dimension, local training, explicit sensitive filters, deterministic test seed. [Mathematics](../../ranking.md).
