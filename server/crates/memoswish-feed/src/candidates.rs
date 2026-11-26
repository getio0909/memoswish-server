//! 完整元数据流上的有界优先队列与惊喜蓄水池，不保留全库正文或全库记忆。

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use memoswish_core::repo::{FeedCardMetadata, Repository};
use memoswish_core::{CoreError, CoreResult, Principal};
use memoswish_protocol::Card;

use crate::engine::{FeedConfig, days_between};
use crate::fsrs::Fsrs;
use crate::rng::SplitMix64;

#[derive(Clone, Debug)]
struct Priority {
    urgency: f64,
    reviewed: DateTime<Utc>,
    created: DateTime<Utc>,
    id: String,
}

impl PartialEq for Priority {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Priority {}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.urgency
            .total_cmp(&other.urgency)
            .then(self.reviewed.cmp(&other.reviewed))
            .then(self.created.cmp(&other.created))
            .then(self.id.cmp(&other.id))
    }
}

#[derive(Default)]
struct RankedPool(BTreeMap<Priority, FeedCardMetadata>);

impl RankedPool {
    fn offer(&mut self, metadata: &FeedCardMetadata, urgency: f64, reviewed: DateTime<Utc>, cap: usize) {
        let key = Priority { urgency, reviewed, created: metadata.created_at, id: metadata.card_id.clone() };
        if self.0.len() == cap && self.0.last_key_value().is_some_and(|(last, _)| &key >= last) {
            return;
        }
        self.0.insert(key, metadata.clone());
        if self.0.len() > cap {
            self.0.pop_last();
        }
    }

    fn into_metadata(self) -> Vec<FeedCardMetadata> {
        self.0.into_values().collect()
    }
}

pub(crate) struct CandidateRequest<'a> {
    pub deck: Option<&'a str>,
    pub now: DateTime<Utc>,
    pub page: usize,
}

pub(crate) struct CandidateSet {
    pub cards: Vec<Card>,
    pub memory: HashMap<String, memoswish_core::repo::MemoryState>,
    pub due: Vec<String>,
    pub fresh: Vec<String>,
    pub reinforce: Vec<String>,
    pub surprise: Vec<String>,
    pub fallback: Vec<String>,
    pub distinct: usize,
    pub fairness: Option<String>,
}

impl CandidateSet {
    pub async fn load(
        repo: &dyn Repository,
        p: &Principal,
        cfg: &FeedConfig,
        fsrs: &Fsrs,
        session: &memoswish_core::repo::FeedSession,
        request: CandidateRequest<'_>,
    ) -> CoreResult<Self> {
        let CandidateRequest { deck, now, page } = request;
        // 每页最多新增 page 个阻挡目标，另保留连续性所需的最大前瞻。
        let cap = cfg.recent_window.saturating_add(page).saturating_add(16);
        let mut due = RankedPool::default();
        let mut fresh = RankedPool::default();
        let mut reinforce = RankedPool::default();
        let mut fallback = RankedPool::default();
        let mut surprise = Vec::new();
        let mut surprise_seen = 0;
        let mut distinct = 0;
        let mut fairness: Option<FeedCardMetadata> = None;
        let mut rng = SplitMix64::from_parts(&session.id, session.next_slot);
        let epoch = DateTime::<Utc>::UNIX_EPOCH;
        repo.visit_feed_metadata(&p.tenant_id, &p.user_id, deck, &mut |metadata| {
            if metadata.suspended || metadata.buried_until_ms.is_some_and(|until| now.timestamp_millis() < until) {
                return Ok(());
            }
            distinct += 1;
            if fairness.as_ref().is_none_or(|old| {
                (metadata.last_issued_seq, metadata.created_at, &metadata.card_id)
                    < (old.last_issued_seq, old.created_at, &old.card_id)
            }) {
                fairness = Some(metadata.clone());
            }
            let last_seen = session
                .recent_card_ids
                .iter()
                .rposition(|id| id == &metadata.card_id)
                .map_or(-1, |position| position as i64);
            fallback.offer(&metadata, last_seen as f64, epoch, cap);
            match &metadata.memory {
                None => fresh.offer(&metadata, 0.0, epoch, cap),
                Some(memory) if memory.reps == 0 => fresh.offer(&metadata, 0.0, epoch, cap),
                Some(memory) => {
                    let r = memory
                        .last_review
                        .map_or(0.0, |review| fsrs.retrievability(days_between(review, now), memory.stability));
                    let is_due = memory.due.is_some_and(|due| due <= now) || r < fsrs.desired_retention;
                    if is_due {
                        due.offer(&metadata, r, epoch, cap);
                    }
                    if memory.starred || memory.last_rating.is_some_and(|rating| rating <= 2) {
                        reinforce.offer(&metadata, 0.0, memory.last_review.unwrap_or(epoch), cap);
                    }
                    if !is_due && (r > 0.95 || memory.starred) {
                        surprise_seen += 1;
                        if surprise.len() < cap {
                            surprise.push(metadata);
                        } else {
                            let position = rng.below(surprise_seen);
                            if position < cap {
                                surprise[position] = metadata;
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;
        let fair_id = fairness.as_ref().map(|m| m.card_id.clone());
        let pools = [
            due.into_metadata(),
            fresh.into_metadata(),
            reinforce.into_metadata(),
            surprise,
            fallback.into_metadata(),
            fairness.into_iter().collect(),
        ];
        let mut memory = HashMap::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut queues = Vec::new();
        for pool in pools {
            let mut queue = Vec::with_capacity(pool.len());
            for metadata in pool {
                ids.insert(metadata.card_id.clone());
                queue.push(metadata.card_id);
                if let Some(state) = metadata.memory {
                    memory.insert(state.card_id.clone(), state);
                }
            }
            queues.push(queue);
        }
        // 上一张可能在优先队列之外，同一批补全保持连续性所需的上下文。
        if let Some(previous) = session.recent_card_ids.last() {
            ids.insert(previous.clone());
        }
        let cards = repo.hydrate_feed_cards(&p.tenant_id, deck, &ids.into_iter().collect::<Vec<_>>()).await?;
        let hydrated: std::collections::HashSet<_> = cards.iter().map(|card| card.id.as_str()).collect();
        if queues.iter().flatten().any(|id| !hydrated.contains(id.as_str())) {
            return Err(CoreError::Unavailable("feed candidates changed; recompute".into()));
        }
        let mut queues = queues.into_iter();
        Ok(Self {
            cards,
            memory,
            distinct,
            fairness: fair_id,
            due: queues.next().unwrap(),
            fresh: queues.next().unwrap(),
            reinforce: queues.next().unwrap(),
            surprise: queues.next().unwrap(),
            fallback: queues.next().unwrap(),
        })
    }
}
