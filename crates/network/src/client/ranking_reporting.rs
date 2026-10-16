use annoda_core::{identity::verify_signature, protocol::ProfileId};
use annoda_intelligence::{
    ranking::{
        CandidateFilter, PhotoEmbedding, PreferenceModel, PreferenceModelSnapshot, RankedCandidate,
        RankingCandidate, RankingError,
    },
    safety::ProfileReport,
};
use serde::Serialize;

use super::{AnnodaClient, ClientError, Page, PageCursor};

const REPORT_DOMAIN: &[u8] = b"annoda/local-report/v1\0";

#[derive(Serialize)]
struct ReportClaims<'a> {
    version: u16,
    report_id: [u8; 16],
    reporter: ProfileId,
    subject: ProfileId,
    policy_reason: u16,
    evidence_hashes: &'a [[u8; 32]],
    created_at: u64,
}

#[derive(serde::Deserialize, Serialize)]
struct ReportCursor {
    version: u16,
    owner: ProfileId,
    created_at: u64,
    report_id: [u8; 16],
}

impl AnnodaClient {
    pub(super) fn score_cached_profile(
        &self,
        peer: ProfileId,
        source_hash: [u8; 32],
    ) -> Result<f64, ClientError> {
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        let Some((version, values)) = storage
            .candidate_embedding(owner, peer, source_hash)
            .map_err(map_error)?
        else {
            return Ok(0.5);
        };
        let embedding = PhotoEmbedding::new(version, values).map_err(map_ranking_error)?;
        match load_model(&storage, owner)? {
            Some(model) => match model.score(&embedding) {
                Ok(score) => Ok(score.probability),
                Err(RankingError::IncompatibleEmbedding) => Ok(0.5),
                Err(error) => Err(map_ranking_error(error)),
            },
            None => Ok(0.5),
        }
    }

    pub(super) fn automatic_feedback(
        &mut self,
        peer: ProfileId,
        liked: bool,
    ) -> Result<(), ClientError> {
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        let Some((_, version, values)) = storage
            .candidate_embedding_any(owner, peer)
            .map_err(map_error)?
        else {
            return Ok(());
        };
        let embedding = PhotoEmbedding::new(version, values).map_err(map_ranking_error)?;
        self.record_feedback(peer, &embedding, liked)
    }

    /// Ranks caller-encoded local embeddings and applies persisted seen-history exclusions.
    pub fn rank_candidates(
        &self,
        candidates: &[RankingCandidate],
        filter: &CandidateFilter,
        exploration_fraction: f64,
        seed: u64,
    ) -> Result<Vec<RankedCandidate>, ClientError> {
        self.account()?;
        if candidates.len() > 512 || filter.coarse_region.is_some() {
            return Err(ClientError::InvalidInput);
        }
        let mut effective_filter = filter.clone();
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        let owner_id = profile_id_string(owner);
        effective_filter.blocked.insert(owner_id);
        for candidate in candidates {
            let Some(peer) = parse_profile_id(&candidate.id) else {
                continue;
            };
            if storage
                .load_match(owner, peer)
                .map_err(map_error)?
                .is_some_and(|record| {
                    matches!(
                        record.state(),
                        annoda_core::matching::MatchState::Blocked
                            | annoda_core::matching::MatchState::Rejected
                    )
                })
            {
                effective_filter.blocked.insert(candidate.id.clone());
            }
        }
        effective_filter.seen.extend(
            storage
                .seen_profiles(owner, 512)
                .map_err(map_error)?
                .iter()
                .map(|profile| profile_id_string(*profile)),
        );
        let model = match load_model(&storage, owner)? {
            Some(model) => model,
            None => {
                let Some(candidate) = candidates.first() else {
                    return Ok(Vec::new());
                };
                PreferenceModel::new(
                    candidate.embedding.values.len(),
                    candidate.embedding.version,
                    0.1,
                    0.01,
                    128,
                )
                .map_err(map_ranking_error)?
            }
        };
        model
            .rank(candidates, &effective_filter, exploration_fraction, seed)
            .map_err(map_ranking_error)
    }

    /// Records explicit swipe feedback and persists the validated local model snapshot.
    pub fn record_feedback(
        &mut self,
        peer: ProfileId,
        embedding: &PhotoEmbedding,
        liked: bool,
    ) -> Result<(), ClientError> {
        let owner = self.owner()?;
        if owner == peer {
            return Err(ClientError::InvalidInput);
        }
        let mut storage = self.open_storage()?;
        if liked {
            let state = storage
                .load_match(owner, peer)
                .map_err(map_error)?
                .map(|record| record.state());
            if !matches!(
                state,
                Some(annoda_core::matching::MatchState::Outgoing)
                    | Some(annoda_core::matching::MatchState::Matched)
            ) {
                return Err(ClientError::Unauthorized);
            }
        }
        let mut model = match load_model(&storage, owner)? {
            Some(model) => model,
            None => PreferenceModel::new(embedding.values.len(), embedding.version, 0.1, 0.01, 128)
                .map_err(map_ranking_error)?,
        };
        model.update(embedding, liked).map_err(map_ranking_error)?;
        model.record_seen(profile_id_string(peer));
        let snapshot = model.snapshot();
        let encoded = postcard::to_allocvec(&snapshot).map_err(|_| ClientError::Internal)?;
        storage
            .apply_feedback_and_model(owner, peer, liked, self.now(), &encoded)
            .map_err(map_error)
            .map(|_| ())
    }

    /// Clears the model and bounded swipe history. The next ranking starts from zero weights.
    pub fn reset_learning(&mut self) -> Result<(), ClientError> {
        let owner = self.owner()?;
        self.open_storage()?
            .reset_local_learning(owner)
            .map_err(map_error)
    }

    /// Creates and stores a bounded signed report. Persistence is LocalOnly; this sends nothing.
    pub fn report_profile(
        &mut self,
        subject: ProfileId,
        policy_reason: u16,
        evidence_hashes: Vec<[u8; 32]>,
    ) -> Result<ProfileReport, ClientError> {
        self.credential()?;
        let reporter = self.owner()?;
        if subject == reporter
            || policy_reason == 0
            || evidence_hashes.is_empty()
            || evidence_hashes.len() > 32
        {
            return Err(ClientError::InvalidInput);
        }
        let mut report_id = [0u8; 16];
        getrandom::fill(&mut report_id).map_err(|_| ClientError::Internal)?;
        let created_at = self.now();
        let claims = ReportClaims {
            version: 1,
            report_id,
            reporter,
            subject,
            policy_reason,
            evidence_hashes: &evidence_hashes,
            created_at,
        };
        let bytes = postcard::to_allocvec(&claims).map_err(|_| ClientError::Internal)?;
        let signature = self.account()?.identity().sign(REPORT_DOMAIN, &bytes);
        let report = ProfileReport {
            version: 1,
            report_id,
            reporter: reporter.0,
            subject: subject.0,
            policy_reason,
            evidence_hashes,
            created_at,
            signature,
        };
        report
            .validate_bounds()
            .map_err(|_| ClientError::InvalidInput)?;
        let encoded = postcard::to_allocvec(&report).map_err(|_| ClientError::Internal)?;
        self.open_storage()?
            .save_local_report(reporter, report_id, &encoded, created_at)
            .map_err(map_error)?;
        Ok(report)
    }

    /// Reads locally stored reports and verifies each account signature before returning it.
    pub fn local_reports(&self, limit: usize) -> Result<Vec<ProfileReport>, ClientError> {
        if limit == 0 || limit > 64 {
            return Err(ClientError::InvalidInput);
        }
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        storage
            .local_reports(owner, limit)
            .map_err(map_error)?
            .into_iter()
            .map(|bytes| {
                let report: ProfileReport =
                    postcard::from_bytes(&bytes).map_err(|_| ClientError::Storage)?;
                report.validate_bounds().map_err(|_| ClientError::Storage)?;
                if report.reporter != owner.0 {
                    return Err(ClientError::UntrustedIdentity);
                }
                let claims = ReportClaims {
                    version: report.version,
                    report_id: report.report_id,
                    reporter: owner,
                    subject: ProfileId(report.subject),
                    policy_reason: report.policy_reason,
                    evidence_hashes: &report.evidence_hashes,
                    created_at: report.created_at,
                };
                let canonical = postcard::to_allocvec(&claims).map_err(|_| ClientError::Storage)?;
                verify_signature(
                    &self.account()?.identity().signing_public_key(),
                    REPORT_DOMAIN,
                    &canonical,
                    &report.signature,
                )
                .map_err(|_| ClientError::UntrustedIdentity)?;
                Ok(report)
            })
            .collect()
    }

    pub fn local_reports_page(
        &self,
        page_size: u8,
        cursor: Option<PageCursor>,
    ) -> Result<Page<ProfileReport>, ClientError> {
        if page_size == 0 || page_size > 64 {
            return Err(ClientError::InvalidInput);
        }
        let owner = self.owner()?;
        let after = cursor
            .map(|cursor| {
                let value: ReportCursor =
                    postcard::from_bytes(&cursor.0).map_err(|_| ClientError::InvalidInput)?;
                if value.version != 1 || value.owner != owner {
                    return Err(ClientError::InvalidInput);
                }
                Ok((value.created_at, value.report_id))
            })
            .transpose()?;
        let storage = self.open_storage()?;
        let mut records = storage
            .local_reports_after(owner, after, page_size as usize + 1)
            .map_err(map_error)?;
        let has_more = records.len() > page_size as usize;
        records.truncate(page_size as usize);
        let next_cursor = if has_more {
            records
                .last()
                .map(|record| {
                    postcard::to_allocvec(&ReportCursor {
                        version: 1,
                        owner,
                        created_at: record.created_at,
                        report_id: record.report_id,
                    })
                    .map(PageCursor)
                    .map_err(|_| ClientError::Internal)
                })
                .transpose()?
        } else {
            None
        };
        let reports = records
            .into_iter()
            .map(|record| decode_signed_report(self, owner, &record.data))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page {
            items: reports,
            next_cursor,
        })
    }
}

fn decode_signed_report(
    client: &AnnodaClient,
    owner: ProfileId,
    bytes: &[u8],
) -> Result<ProfileReport, ClientError> {
    let report: ProfileReport = postcard::from_bytes(bytes).map_err(|_| ClientError::Storage)?;
    report.validate_bounds().map_err(|_| ClientError::Storage)?;
    if report.reporter != owner.0 {
        return Err(ClientError::UntrustedIdentity);
    }
    let claims = ReportClaims {
        version: report.version,
        report_id: report.report_id,
        reporter: owner,
        subject: ProfileId(report.subject),
        policy_reason: report.policy_reason,
        evidence_hashes: &report.evidence_hashes,
        created_at: report.created_at,
    };
    let canonical = postcard::to_allocvec(&claims).map_err(|_| ClientError::Storage)?;
    verify_signature(
        &client.account()?.identity().signing_public_key(),
        REPORT_DOMAIN,
        &canonical,
        &report.signature,
    )
    .map_err(|_| ClientError::UntrustedIdentity)?;
    Ok(report)
}

fn load_model(
    storage: &annoda_core::storage::PeerStorage,
    owner: ProfileId,
) -> Result<Option<PreferenceModel>, ClientError> {
    let Some(bytes) = storage.load_preference_model(owner).map_err(map_error)? else {
        return Ok(None);
    };
    let snapshot: PreferenceModelSnapshot =
        postcard::from_bytes(&bytes).map_err(|_| ClientError::Storage)?;
    PreferenceModel::from_snapshot(snapshot)
        .map(Some)
        .map_err(|_| ClientError::Storage)
}

fn profile_id_string(profile: ProfileId) -> String {
    profile.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_profile_id(value: &str) -> Option<ProfileId> {
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(ProfileId(bytes))
}

fn map_ranking_error(_error: RankingError) -> ClientError {
    ClientError::InvalidInput
}

fn map_error(error: annoda_core::Error) -> ClientError {
    match error {
        annoda_core::Error::InvalidInput | annoda_core::Error::LimitExceeded => {
            ClientError::InvalidInput
        }
        annoda_core::Error::Unauthorized | annoda_core::Error::NotFound => {
            ClientError::Unauthorized
        }
        annoda_core::Error::InvalidCredential | annoda_core::Error::InvalidSignature => {
            ClientError::UntrustedIdentity
        }
        annoda_core::Error::InvalidTime => ClientError::CredentialExpired,
        annoda_core::Error::Storage(_) => ClientError::Storage,
        _ => ClientError::Internal,
    }
}
