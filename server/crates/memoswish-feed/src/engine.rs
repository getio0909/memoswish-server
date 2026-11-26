//! 信息流生成与埋点消费。

#![warn(clippy::disallowed_methods)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use memoswish_core::ids::new_id;
use memoswish_core::repo::{
    FeedIssuanceCandidate, FeedIssuanceOutcome, FeedIssuanceRequest, FeedSession, FeedbackEventRecord,
    LearningEventOutcome, MemoryState, Repository,
};
use memoswish_core::{CoreError, CoreResult, Permission, Principal};
use memoswish_protocol::{
    AssetRef, Card, FeedItem, FeedPage, FeedQuery, FeedReason, FeedbackAck, FeedbackBatch, MAX_FEEDBACK_BATCH,
    PrefetchEntry, PrefetchManifest, RejectedEvent,
};
use serde::{Deserialize, Serialize};

use crate::fsrs::{Fsrs, Memory, Rating};
use crate::rng::SplitMix64;
use crate::signals::SignalPolicy;

/// 信息流参数。全部可通过 memoswishd 配置文件 `[feed]` 段覆盖，便于按场景 / A/B 实验调参。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedConfig {
    pub default_page: u32,
    pub max_page: u32,
    pub window_before: u8,
    pub window_after: u8,
    /// 可变奖赏：每个 slot 插入惊喜卡的概率。
    pub surprise_rate: f64,
    /// 到期 / 新卡 / 强化桶的基础权重。
    pub due_weight: f64,
    pub new_weight: f64,
    pub reinforce_weight: f64,
    /// 会话内近期去重窗口。
    pub recent_window: usize,
    /// 已弃用的旧扫描上限，仅保留配置兼容；不再限制候选、统计或重点库覆盖范围。
    pub scan_limit: u32,
    /// 期望记忆保持率（FSRS desired retention）。
    pub desired_retention: f64,
    /// FSRS 参数向量；为空时使用上游默认参数（适合大多数人），可填入优化器结果。
    pub fsrs_parameters: Vec<f32>,
    pub signals: SignalPolicy,
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            default_page: 10,
            max_page: 50,
            window_before: 3,
            window_after: 5,
            surprise_rate: 0.12,
            due_weight: 0.55,
            new_weight: 0.35,
            reinforce_weight: 0.10,
            recent_window: 20,
            scan_limit: 5_000,
            desired_retention: 0.9,
            fsrs_parameters: vec![],
            signals: SignalPolicy::default(),
        }
    }
}

impl FeedConfig {
    /// 在组装仓储前验证可恢复策略与客户端资源上限。
    pub fn validate(&self) -> CoreResult<()> {
        if self.default_page == 0
            || self.default_page > self.max_page
            || self.max_page > 50
            || self.window_before > 3
            || self.window_after > 5
            || self.window_before.checked_add(self.window_after).and_then(|v| v.checked_add(1)).is_none()
            || self.recent_window == 0
            || self.recent_window > 100
        {
            return Err(CoreError::invalid("feed page, window or history exceeds supported bounds"));
        }
        if self.fsrs_parameters.iter().any(|v| !v.is_finite()) {
            return Err(CoreError::invalid("FSRS parameters must be finite"));
        }
        if !(0.0..=1.0).contains(&self.surprise_rate) {
            return Err(CoreError::invalid("feed.surprise_rate must be within [0, 1]"));
        }
        let total_weight = self.due_weight + self.new_weight + self.reinforce_weight;
        // JSON 不能无损保存非有限浮点值，不能签发无法恢复的策略快照。
        if [self.due_weight, self.new_weight, self.reinforce_weight]
            .iter()
            .any(|weight| !weight.is_finite() || *weight < 0.0)
            || !total_weight.is_finite()
            || total_weight <= 0.0
        {
            return Err(CoreError::invalid("feed bucket weights must be finite and sum to a positive finite number"));
        }
        Fsrs::new(&self.fsrs_parameters, self.desired_retention)?;
        self.signals.validate()?;
        Ok(())
    }
}

pub use memoswish_protocol::LearningStats;

/// 策略快照包含实际页预算和候选范围，不含客户端凭据或动态资产地址。
#[derive(Clone, Serialize, Deserialize)]
struct IssuedPolicy {
    configuration: FeedConfig,
    effective_page_limit: u32,
    deck_id: Option<String>,
}

/// 信息流服务。
#[derive(Clone)]
pub struct FeedService {
    pub(crate) repo: Arc<dyn Repository>,
    observer: Arc<dyn memoswish_core::observability::Observer>,
    pub(crate) cfg: FeedConfig,
    fsrs: Fsrs,
    clock: Arc<dyn memoswish_core::repo::UtcClock>,
    coordinator: Arc<crate::coordinator::Coordinator>,
    #[cfg(test)]
    feedback_gate: Option<Arc<tests::FeedbackGate>>,
    #[cfg(test)]
    stats_gate: Option<Arc<tokio::sync::Barrier>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Bucket {
    Due,
    New,
    Reinforce,
    Surprise,
}

impl Bucket {
    fn reason(self) -> FeedReason {
        match self {
            Bucket::Due => FeedReason::Due,
            Bucket::New => FeedReason::New,
            Bucket::Reinforce => FeedReason::Reinforce,
            Bucket::Surprise => FeedReason::Surprise,
        }
    }
}

pub(crate) fn days_between(a: DateTime<Utc>, b: DateTime<Utc>) -> f64 {
    (b - a).num_milliseconds() as f64 / 86_400_000.0
}

/// 计算候选卡片与上一张卡片的主题连续性得分：
/// 优先匹配相同的非空 `bgm.theme_key`（得分 2），其次匹配相同的 `deck_id`（得分 1），否则为 0。
fn continuity_score(prev: &Card, candidate: &Card) -> u8 {
    let prev_theme = prev.bgm.as_ref().map(|b| b.theme_key.as_str()).filter(|k| !k.is_empty());
    let cand_theme = candidate.bgm.as_ref().map(|b| b.theme_key.as_str()).filter(|k| !k.is_empty());
    if let (Some(pt), Some(ct)) = (prev_theme, cand_theme)
        && pt == ct
    {
        return 2;
    }
    if prev.deck_id == candidate.deck_id {
        return 1;
    }
    0
}

/// 在桶的候选队列中挑选下一张卡：若存在上一张卡片，则在头部优先窗口内优先延续相同 BGM 主题或卡组。
fn pick_with_continuity(bucket: Bucket, queue: &[&Card], eligible: &[usize], prev: Option<&Card>) -> usize {
    let Some(prev_card) = prev else {
        return eligible[0];
    };
    // 新卡桶无复习紧迫度差异，可在更大窗口内寻找同主题卡片；到期与强化桶仅在前若干名候选间平滑打破平局。
    let lookahead = if bucket == Bucket::New { eligible.len().min(16) } else { eligible.len().min(4) };
    let mut best_idx = eligible[0];
    let mut best_score = continuity_score(prev_card, queue[best_idx]);
    for &idx in &eligible[1..lookahead] {
        let score = continuity_score(prev_card, queue[idx]);
        if score > best_score {
            best_score = score;
            best_idx = idx;
            if best_score == 2 {
                break;
            }
        }
    }
    best_idx
}

/// 收集卡片上需要预加载的资产。
fn card_assets(card: &Card) -> Vec<AssetRef> {
    let mut v = Vec::new();
    if let Some(t) = &card.tts {
        v.push(t.audio.clone());
    }
    if let Some(b) = &card.bgm {
        v.push(b.track.asset.clone());
    }
    let block_assets = card.front.blocks.iter().chain(card.back.blocks.iter()).filter_map(|b| b.asset());
    for img in block_assets.chain(card.visual.image.as_ref()) {
        if !v.iter().any(|a: &AssetRef| a.sha256 == img.sha256) {
            v.push(img.clone());
        }
    }
    v
}

// 一次预算覆盖 CAS、数据库可重试冲突及重新计算，不引入第二层重试或计时器。
const TRANSACTION_ATTEMPTS: usize = 8;
const LEGACY_ISSUED_POLICY_VERSION: &str = "delivery-v1-fsrs6.6.2-adapter2-signals1-chronology1-days1-feed1";
const ISSUED_POLICY_VERSION: &str = "delivery-v1-fsrs6.6.2-adapter2-signals1-chronology1-days1-feed2";

async fn retry_learning<F, Fut>(mut attempt: F) -> CoreResult<LearningEventOutcome>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = CoreResult<LearningEventOutcome>>,
{
    for _ in 0..TRANSACTION_ATTEMPTS {
        let outcome = attempt().await?;
        if outcome != LearningEventOutcome::Retry {
            return Ok(outcome);
        }
    }
    Err(CoreError::Unavailable("learning projection contention; retry the batch".into()))
}

// 重试预算和计数属于整次 read/generate/commit 尝试，存储层仅返回类型化原因。
async fn retry_issuance<F, Fut>(
    observer: &dyn memoswish_core::observability::Observer,
    mut command: F,
) -> CoreResult<FeedPage>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = CoreResult<FeedIssuanceOutcome>>,
{
    for _ in 0..TRANSACTION_ATTEMPTS {
        let result = command().await;
        match result {
            Ok(FeedIssuanceOutcome::Committed(page)) => return Ok(page),
            // 唯一计数点：每个失败预算槽只记录一次，包含最后一次耗尽。
            Ok(FeedIssuanceOutcome::Retry(cause)) | Err(CoreError::FeedRetry(cause)) => {
                observer.feed_retry(cause);
            }
            Ok(FeedIssuanceOutcome::Ready(_)) | Err(CoreError::Unavailable(_)) => {
                observer.feed_retry(memoswish_core::observability::FeedRetryCause::Other);
            }
            Err(error) => return Err(error),
        }
    }
    Err(CoreError::Unavailable("feed issuance contention; retry the same request".into()))
}

impl FeedService {
    /// 创建服务；FSRS 参数或保持率非法时返回错误。
    pub fn new(
        repo: Arc<dyn Repository>,
        cfg: FeedConfig,
        clock: Arc<dyn memoswish_core::repo::UtcClock>,
    ) -> CoreResult<Self> {
        cfg.validate()?;
        let fsrs = Fsrs::new(&cfg.fsrs_parameters, cfg.desired_retention)?;
        Ok(Self {
            observer: memoswish_core::observability::noop(),
            repo,
            cfg,
            fsrs,
            clock,
            coordinator: Arc::new(crate::coordinator::Coordinator::default()),
            #[cfg(test)]
            feedback_gate: None,
            #[cfg(test)]
            stats_gate: None,
        })
    }

    pub fn with_observer(mut self, observer: Arc<dyn memoswish_core::observability::Observer>) -> Self {
        self.observer = observer;
        self
    }

    pub fn config(&self) -> &FeedConfig {
        &self.cfg
    }

    fn retrievability(&self, m: &MemoryState, now: DateTime<Utc>) -> f64 {
        match m.last_review {
            Some(t) => self.fsrs.retrievability(days_between(t, now), m.stability),
            None => 0.0,
        }
    }

    /// 恢复不可变回执，或在一次有界预算内计算并条件提交新页。
    pub async fn next_page(&self, p: &Principal, q: &FeedQuery) -> CoreResult<FeedPage> {
        p.require(Permission::FeedRead)?;
        match q.mode.as_deref() {
            Some("preview") => return self.preview(p, q).await,
            None | Some("learning") => {}
            Some(_) => return Err(CoreError::invalid("unknown feed mode")),
        }
        // 在借用数据库连接前排队，跨重算和提交持有同一学习者 guard。
        let _learner = self.coordinator.acquire(&p.tenant_id, &p.user_id).await?;
        let now = self.clock.now();
        let request = FeedIssuanceRequest {
            query: q.clone(),
            new_session_id: format!("sess_{}", new_id()),
            legacy_request_id: new_id(),
            now,
        };
        retry_issuance(self.observer.as_ref(), || async {
            let state = match self.repo.feed_issuance(p, &request, None).await? {
                FeedIssuanceOutcome::Committed(page) => return Ok(FeedIssuanceOutcome::Committed(page)),
                FeedIssuanceOutcome::Ready(state) => state,
                FeedIssuanceOutcome::Retry(cause) => return Ok(FeedIssuanceOutcome::Retry(cause)),
            };
            let mut effective = self.clone();
            effective.cfg.desired_retention = state.desired_retention.unwrap_or(self.cfg.desired_retention);
            effective.fsrs = Fsrs::new(&self.cfg.fsrs_parameters, effective.cfg.desired_retention)?;
            let mut configuration = effective.cfg.clone();
            configuration.fsrs_parameters = effective.fsrs.parameters().to_vec();
            let policy = memoswish_core::repo::DeliveryPolicy::new(
                ISSUED_POLICY_VERSION,
                &IssuedPolicy {
                    effective_page_limit: q
                        .limit
                        .unwrap_or(configuration.default_page)
                        .clamp(1, configuration.max_page),
                    deck_id: q.deck_id.clone(),
                    configuration,
                },
            )?;

            let (mut page, successor) = effective.generate_page(p, q, state.session.clone(), now).await?;
            if state.replayable {
                page.next_cursor = format!("fp_{}", new_id());
            }
            page.mode = Some("learning".into());
            page.policy_version = Some(policy.version.clone());
            for item in &mut page.items {
                item.delivery_id = Some(format!("dlv_{}", new_id()));
            }
            let candidate = FeedIssuanceCandidate { policy: Some(policy.clone()), expected: state, successor, page };
            self.repo.feed_issuance(p, &request, Some(&candidate)).await
        })
        .await
    }

    /// 预览只读取候选，不创建学习会话、回执或投递记录。
    pub async fn preview(&self, p: &Principal, q: &FeedQuery) -> CoreResult<FeedPage> {
        self.repo.authorize_feed_preview(p).await?;
        let now = self.clock.now();
        let session = FeedSession {
            id: "preview:non-learning".into(),
            tenant_id: p.tenant_id.clone(),
            user_id: p.user_id.clone(),
            next_slot: 0,
            recent_card_ids: vec![],
            created_at: now,
            updated_at: now,
        };
        let (mut page, _) = self.generate_page(p, q, session, now).await?;
        // 返回前再次核验撤销，不能用旧主体读取新的凭据世代。
        self.repo.authorize_feed_preview(p).await?;
        page.mode = Some("preview".into());
        page.next_cursor.clear();
        Ok(page)
    }

    async fn generate_page(
        &self,
        p: &Principal,
        q: &FeedQuery,
        mut session: FeedSession,
        now: DateTime<Utc>,
    ) -> CoreResult<(FeedPage, FeedSession)> {
        let limit = q.limit.unwrap_or(self.cfg.default_page).clamp(1, self.cfg.max_page) as usize;
        let candidates = crate::candidates::CandidateSet::load(
            self.repo.as_ref(),
            p,
            &self.cfg,
            &self.fsrs,
            &session,
            crate::candidates::CandidateRequest { deck: q.deck_id.as_deref(), now, page: limit },
        )
        .await?;
        let cards = &candidates.cards;
        let memory = &candidates.memory;
        let by_id: HashMap<&str, &Card> = cards.iter().map(|card| (card.id.as_str(), card)).collect();
        let resolve = |ids: &[String]| ids.iter().filter_map(|id| by_id.get(id.as_str()).copied()).collect::<Vec<_>>();
        let queues: HashMap<Bucket, Vec<&Card>> = HashMap::from([
            (Bucket::Due, resolve(&candidates.due)),
            (Bucket::New, resolve(&candidates.fresh)),
            (Bucket::Reinforce, resolve(&candidates.reinforce)),
            (Bucket::Surprise, resolve(&candidates.surprise)),
        ]);
        let fallback = resolve(&candidates.fallback);

        // ---- 逐 slot 调度 ----
        let mut items = Vec::with_capacity(limit);
        let distinct_cards = candidates.distinct;
        // 最近窗口仅影响加权选择；每页硬去重与新卡预算也约束回退。
        let window = self.cfg.recent_window.min(distinct_cards.saturating_sub(1));
        let mut delivered = HashSet::<String>::new();
        let mut new_count = 0;
        for index in 0..limit {
            if distinct_cards == 0 {
                break;
            }
            let history = &session.recent_card_ids;
            let blocked: HashSet<&str> = history.iter().rev().take(window).map(String::as_str).collect();
            let slot = session.next_slot;
            let mut rng = SplitMix64::from_parts(&session.id, slot);
            let order = self.bucket_order(&mut rng);
            let is_new = |card: &Card| memory.get(&card.id).is_none_or(|m| m.reps == 0);
            let allowed = |card: &Card| !delivered.contains(&card.id) && (!is_new(card) || new_count < 4);
            // 首位独立于截断池及最近窗口，保证固定有限候选域最多 N 个非空新页覆盖。
            let mut picked: Option<(Bucket, &Card)> = if index == 0 {
                candidates
                    .fairness
                    .as_ref()
                    .and_then(|id| by_id.get(id.as_str()))
                    .map(|card| (if is_new(card) { Bucket::New } else { Bucket::Due }, *card))
            } else {
                None
            };
            for b in order {
                if picked.is_some() {
                    break;
                }
                let Some(queue) = queues.get(&b) else { continue };
                let eligible: Vec<usize> = queue
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| allowed(c) && !blocked.contains(c.id.as_str()))
                    .map(|(i, _)| i)
                    .collect();
                if eligible.is_empty() {
                    continue;
                }
                // 惊喜桶随机抽取，其它桶按优先级并结合上一张卡的 BGM 主题 / 卡组连续性挑选候选。
                let prev_card = session.recent_card_ids.last().and_then(|id| cards.iter().find(|c| &c.id == id));
                let idx = if b == Bucket::Surprise {
                    eligible[rng.below(eligible.len())]
                } else {
                    pick_with_continuity(b, queue, &eligible, prev_card)
                };
                picked = Some((b, queue[idx]));
                break;
            }
            // 所有桶都被去重挡住时，回退为“最久未出现”的卡片复习。
            let (bucket, card) = match picked {
                Some(x) => x,
                None => {
                    let last_seen = |id: &str| history.iter().rposition(|h| h == id).map_or(-1, |p| p as i64);
                    let Some(c) = fallback.iter().copied().filter(|c| allowed(c)).min_by_key(|c| last_seen(&c.id))
                    else {
                        break;
                    };
                    (Bucket::Due, c)
                }
            };
            new_count += usize::from(is_new(card));
            delivered.insert(card.id.clone());
            items.push(FeedItem {
                delivery_id: None,
                slot,
                reason: bucket.reason(),
                card: card.clone(),
                retrievability: memory.get(&card.id).map(|m| self.retrievability(m, now) as f32),
            });
            session.next_slot += 1;
            session.recent_card_ids.push(card.id.clone());
        }
        let cap = self.cfg.recent_window.max(50);
        if session.recent_card_ids.len() > cap {
            let drop = session.recent_card_ids.len() - cap;
            session.recent_card_ids.drain(..drop);
        }
        session.updated_at = now;

        let entries = items
            .iter()
            .enumerate()
            .map(|(i, it)| PrefetchEntry {
                slot: it.slot,
                card_id: it.card.id.clone(),
                priority: i.min(255) as u8,
                assets: card_assets(&it.card),
            })
            .collect();
        let page = FeedPage {
            mode: None,
            policy_version: None,
            session_id: session.id.clone(),
            next_cursor: format!("s:{}", session.next_slot),
            items,
            prefetch: PrefetchManifest {
                window_before: self.cfg.window_before,
                window_after: self.cfg.window_after,
                entries,
                expires_at: None,
            },
            generated_at: now,
        };
        Ok((page, session))
    }

    /// 按可变奖赏策略给出本 slot 的桶尝试顺序。
    fn bucket_order(&self, rng: &mut SplitMix64) -> Vec<Bucket> {
        let mut order = Vec::with_capacity(4);
        if rng.next_f64() < self.cfg.surprise_rate {
            order.push(Bucket::Surprise);
        }
        let total = self.cfg.due_weight + self.cfg.new_weight + self.cfg.reinforce_weight;
        let x = rng.next_f64() * total;
        let first = if x < self.cfg.due_weight {
            Bucket::Due
        } else if x < self.cfg.due_weight + self.cfg.new_weight {
            Bucket::New
        } else {
            Bucket::Reinforce
        };
        order.push(first);
        for b in [Bucket::Due, Bucket::New, Bucket::Reinforce, Bucket::Surprise] {
            if !order.contains(&b) {
                order.push(b);
            }
        }
        order
    }

    /// 消费一批无感埋点：幂等入库并更新 FSRS 记忆状态。
    pub async fn record_feedback(&self, p: &Principal, batch: &FeedbackBatch) -> CoreResult<FeedbackAck> {
        let now = self.clock.now();
        self.record_feedback_at(p, batch, now).await
    }

    async fn record_feedback_at(
        &self,
        p: &Principal,
        batch: &FeedbackBatch,
        now: DateTime<Utc>,
    ) -> CoreResult<FeedbackAck> {
        use memoswish_core::observability::ReviewOutcome;
        p.require(Permission::FeedbackWrite)?;
        if batch.events.len() > MAX_FEEDBACK_BATCH {
            return Err(CoreError::invalid(format!("at most {MAX_FEEDBACK_BATCH} events per batch")));
        }
        let mut ack = FeedbackAck::default();
        let mut events: Vec<_> = batch.events.iter().collect();
        events.sort_by_key(|e| (e.shown_at, &e.event_id));
        for e in events {
            if e.event_id.is_empty() || e.event_id.len() > 64 {
                self.observer.review(ReviewOutcome::Rejected);
                ack.rejected.push(RejectedEvent { event_id: e.event_id.clone(), reason: "invalid event_id".into() });
                continue;
            }
            if !e.swipe_velocity.is_finite() || e.swipe_velocity < 0.0 {
                self.observer.review(ReviewOutcome::Rejected);
                ack.rejected
                    .push(RejectedEvent { event_id: e.event_id.clone(), reason: "invalid swipe_velocity".into() });
                continue;
            }
            let mut record = FeedbackEventRecord {
                tenant_id: p.tenant_id.clone(),
                user_id: p.user_id.clone(),
                session_id: batch.session_id.clone(),
                event: e.clone(),
                rating: None,
                received_at: now,
                application: None,
            };
            match self.repo.recover_learning_event(p, &record).await? {
                Some(LearningEventOutcome::Duplicate) => {
                    self.observer.review(ReviewOutcome::Duplicate);
                    ack.duplicates += 1;
                    continue;
                }
                Some(LearningEventOutcome::PayloadConflict) => {
                    self.observer.review(ReviewOutcome::Rejected);
                    ack.rejected.push(RejectedEvent { event_id: e.event_id.clone(), reason: "conflict".into() });
                    continue;
                }
                Some(_) => return Err(CoreError::internal("invalid learning receipt outcome")),
                None => {}
            }
            let delivery = self.repo.get_delivery(&p.tenant_id, &p.user_id, &batch.session_id, e.slot).await?;
            let configuration = delivery
                .as_ref()
                .map(|d| {
                    if ![ISSUED_POLICY_VERSION, LEGACY_ISSUED_POLICY_VERSION]
                        .iter()
                        .any(|version| d.policy.version.starts_with(&format!("{version}:")))
                    {
                        return Err(CoreError::Unavailable("unsupported issued delivery policy".into()));
                    }
                    d.policy.decode::<IssuedPolicy>().map(|issued| issued.configuration)
                })
                .transpose()?;
            let signals = configuration.as_ref().map_or(&self.cfg.signals, |cfg| &cfg.signals);
            let issued_fsrs =
                configuration.as_ref().map(|cfg| Fsrs::new(&cfg.fsrs_parameters, cfg.desired_retention)).transpose()?;
            let fsrs = issued_fsrs.as_ref().unwrap_or(&self.fsrs);
            let outcome = signals.interpret(e);
            record.rating = outcome.rating.map(|r| r as u8);
            let applied = retry_learning(|| async {
                let snapshot = self.repo.get_versioned_memory(&p.tenant_id, &p.user_id, &e.card_id).await?;
                #[cfg(test)]
                if let Some(gate) = &self.feedback_gate {
                    gate.after_read(&snapshot).await;
                }
                let expected = snapshot.as_ref().map(|m| m.version);
                let mut state = snapshot.map(|m| m.state).unwrap_or(MemoryState {
                    tenant_id: p.tenant_id.clone(),
                    user_id: p.user_id.clone(),
                    card_id: e.card_id.clone(),
                    stability: 0.0,
                    difficulty: 0.0,
                    reps: 0,
                    lapses: 0,
                    exposures: 0,
                    last_review: None,
                    due: None,
                    starred: false,
                    last_rating: None,
                });
                let mut application =
                    crate::learning_policy::application(e, now, state.last_review, outcome, signals, fsrs);
                if let Some(delivery) = &delivery {
                    application.attribution_source = "issued_delivery_policy".into();
                    application.issued_delivery = Some(delivery.attribution.clone());
                }
                state.exposures += 1;
                state.starred |= outcome.star;
                if let (Some(r), Some(reviewed_at)) = (outcome.rating, application.effective_at) {
                    let (previous, elapsed) = match state.last_review {
                        Some(last) if state.reps > 0 => (
                            Some(Memory { stability: state.stability, difficulty: state.difficulty }),
                            days_between(last, reviewed_at).max(0.0),
                        ),
                        _ => (None, 0.0),
                    };
                    let review = fsrs.review(previous, elapsed, r)?;
                    let mem = review.memory;
                    if r == Rating::Again && state.reps > 0 {
                        state.lapses += 1;
                    }
                    state.stability = mem.stability;
                    state.difficulty = mem.difficulty;
                    state.reps += 1;
                    state.last_review = Some(reviewed_at);
                    state.last_rating = Some(r as u8);
                    let ivl = review.interval_days;
                    state.due = Some(reviewed_at + Duration::milliseconds((ivl * 86_400_000.0) as i64));
                }
                let mut record = record.clone();
                let disposition = application.disposition;
                record.application = Some(application);
                let result = self.repo.try_apply_learning_event_for_principal(p, &record, expected, &state).await;
                if matches!(result, Ok(LearningEventOutcome::Applied)) {
                    self.observer.disposition(disposition);
                }
                #[cfg(test)]
                if let (Some(gate), Ok(outcome)) = (&self.feedback_gate, &result) {
                    gate.outcomes.lock().unwrap().push(*outcome);
                }
                result
            })
            .await?;
            match applied {
                LearningEventOutcome::Applied => {
                    self.observer.review(ReviewOutcome::Accepted);
                    ack.accepted += 1;
                }
                LearningEventOutcome::Duplicate => {
                    self.observer.review(ReviewOutcome::Duplicate);
                    ack.duplicates += 1;
                }
                LearningEventOutcome::PayloadConflict => {
                    self.observer.review(ReviewOutcome::Rejected);
                    ack.rejected.push(RejectedEvent { event_id: e.event_id.clone(), reason: "conflict".into() })
                }
                LearningEventOutcome::MissingCard => {
                    self.observer.review(ReviewOutcome::Rejected);
                    ack.rejected.push(RejectedEvent { event_id: e.event_id.clone(), reason: "unknown card".into() })
                }
                LearningEventOutcome::InvalidDelivery => {
                    self.observer.review(ReviewOutcome::Rejected);
                    ack.rejected.push(RejectedEvent {
                        event_id: e.event_id.clone(),
                        reason: "invalid delivery binding".into(),
                    });
                }
                LearningEventOutcome::MissingScope => {
                    self.observer.review(ReviewOutcome::Rejected);
                    return Err(CoreError::Forbidden("learning scope no longer exists".into()));
                }
                LearningEventOutcome::Retry => unreachable!("retry budget returns an error"),
            }
        }
        Ok(ack)
    }

    /// 学习统计（全局）。
    pub async fn stats(&self, p: &Principal) -> CoreResult<LearningStats> {
        self.stats_for_deck(p, None).await
    }

    /// 按可选卡组过滤的学习统计。
    pub async fn stats_for_deck(&self, p: &Principal, deck_id: Option<&str>) -> CoreResult<LearningStats> {
        p.require(Permission::FeedRead)?;
        let now = self.clock.now();
        self.stats_for_deck_at(p, deck_id, now).await
    }

    async fn stats_for_deck_at(
        &self,
        p: &Principal,
        deck_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> CoreResult<LearningStats> {
        let mut stats = LearningStats {
            total_cards: 0,
            seen_cards: 0,
            due_cards: 0,
            starred_cards: 0,
            total_exposures: 0,
            average_retrievability: 0.0,
        };
        let mut retrievability = 0.0;
        #[cfg(test)]
        if let Some(gate) = &self.stats_gate {
            gate.wait().await;
            gate.wait().await;
        }
        // 全部字段只消费同一条查询的快照，避免并发反馈或删除割裂汇总与 FSRS 输入。
        self.repo
            .visit_feed_metadata(&p.tenant_id, &p.user_id, deck_id, &mut |metadata| {
                stats.total_cards = stats
                    .total_cards
                    .checked_add(1)
                    .ok_or_else(|| CoreError::internal("learning count exceeds protocol range"))?;
                if let Some(memory) = metadata.memory {
                    stats.starred_cards += u32::from(memory.starred);
                    stats.total_exposures = stats
                        .total_exposures
                        .checked_add(u64::from(memory.exposures))
                        .ok_or_else(|| CoreError::internal("learning exposure total exceeds protocol range"))?;
                    if memory.reps == 0 {
                        return Ok(());
                    }
                    stats.seen_cards += 1;
                    retrievability += self.retrievability(&memory, now);
                    stats.due_cards += u32::from(memory.due.is_some_and(|due| due <= now));
                }
                Ok(())
            })
            .await?;
        stats.average_retrievability =
            if stats.seen_cards == 0 { 0.0 } else { (retrievability / f64::from(stats.seen_cards)) as f32 };
        Ok(stats)
    }

    /// 完整重点库由带活卡关联的存储查询提供，响应仍为未分页数组。
    pub async fn list_starred_cards(&self, p: &Principal, deck_id: Option<&str>) -> CoreResult<Vec<Card>> {
        p.require(Permission::FeedRead)?;
        self.repo.starred_feed_cards(&p.tenant_id, &p.user_id, deck_id).await
    }

    /// 根据学习者历史记忆状态（平均稳定性、难度与遗忘率）动态推荐最优 FSRS-6 期望保持率（`[0.80, 0.95]`）。
    /// 已复习卡片不足 5 张时返回配置的默认保持率。
    pub async fn recommended_retention(&self, p: &Principal) -> CoreResult<f32> {
        p.require(Permission::FeedRead)?;
        let all_mem = self.repo.list_memory(&p.tenant_id, &p.user_id).await?;
        let reviewed: Vec<_> = all_mem.into_iter().filter(|m| m.reps > 0).collect();
        if reviewed.len() < 5 {
            return Ok((self.cfg.desired_retention as f32).clamp(0.80, 0.95));
        }
        let n = reviewed.len() as f64;
        let avg_stability = reviewed.iter().map(|m| m.stability).sum::<f64>() / n;
        let avg_difficulty = reviewed.iter().map(|m| m.difficulty).sum::<f64>() / n;
        let total_reps: u64 = reviewed.iter().map(|m| m.reps as u64).sum();
        let total_lapses: u64 = reviewed.iter().map(|m| m.lapses as u64).sum();
        let lapse_rate = if total_reps > 0 { total_lapses as f64 / total_reps as f64 } else { 0.0 };

        // 稳定性越高、难度越低、遗忘率越低，可承受更高的期望保持率；反之适度下调以防复习积压雪崩。
        let stability_adj = ((avg_stability.ln_1p() - 1.5) * 0.012).clamp(-0.03, 0.03);
        let difficulty_adj = ((5.5 - avg_difficulty) * 0.008).clamp(-0.04, 0.03);
        let lapse_adj = (-lapse_rate * 0.10).clamp(-0.06, 0.0);
        let rec = (self.cfg.desired_retention + stability_adj + difficulty_adj + lapse_adj).clamp(0.80, 0.95);
        Ok(rec as f32)
    }
}

#[cfg(test)]
mod tests {
    include!("quality_tests.rs");
    include!("hf12_tests.rs");
    fn test_now() -> chrono::DateTime<chrono::Utc> {
        "2026-11-07T12:00:00Z".parse().unwrap()
    }
    use super::*;
    use memoswish_core::repo::VersionedMemory;
    use memoswish_protocol::{CardFace, Deck, ImplicitFeedback, SwipeDirection, examples};
    use memoswish_storage::sqlite::SqliteRepository;
    use std::sync::Mutex;
    use tokio::sync::{Notify, Semaphore};

    // 每个请求只暂停首次读取，后续快照与真实仓储结果用于证明重读重算路径。
    pub(super) struct FeedbackGate {
        snapshots: Mutex<Vec<Option<VersionedMemory>>>,
        pub(super) outcomes: Mutex<Vec<LearningEventOutcome>>,
        reached: Notify,
        resume: Semaphore,
    }

    impl FeedbackGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                snapshots: Mutex::new(Vec::new()),
                outcomes: Mutex::new(Vec::new()),
                reached: Notify::new(),
                resume: Semaphore::new(0),
            })
        }

        pub(super) async fn after_read(&self, snapshot: &Option<VersionedMemory>) {
            let first = {
                let mut snapshots = self.snapshots.lock().unwrap();
                snapshots.push(snapshot.clone());
                snapshots.len() == 1
            };
            if first {
                self.reached.notify_one();
                self.resume.acquire().await.unwrap().forget();
            }
        }
    }

    async fn seeded(n: usize) -> (FeedService, Arc<dyn Repository>, Principal) {
        seeded_in(Arc::new(SqliteRepository::in_memory().await.unwrap()), n).await
    }

    async fn delivery_policy_and_binding(backend: Arc<dyn Repository>) {
        let (feed, repo, p) = seeded_in(backend, 2).await;
        let query = FeedQuery { request_id: Some("s12-policy".into()), limit: Some(4), ..Default::default() };
        let page = feed.next_page(&p, &query).await.unwrap();
        assert_eq!(page.generated_at, test_now());
        assert_eq!(page.mode.as_deref(), Some("learning"));
        let identities: HashSet<_> = page.items.iter().map(|item| item.delivery_id.as_ref().unwrap()).collect();
        assert_eq!(identities.len(), 2);
        // 小牌组每页仅发不同卡片，投递身份仍彼此独立。
        assert_eq!(page.items.iter().map(|item| &item.card.id).collect::<HashSet<_>>().len(), 2);
        let item = &page.items[0];
        let original = repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, item.slot).await.unwrap().unwrap();
        let mut config = FeedConfig { desired_retention: 0.75, ..Default::default() };
        config.signals.fast_swipe_ms = 10_000;
        config.signals.slow_flip_ms = 20_000;
        config.fsrs_parameters = fsrs::DEFAULT_PARAMETERS.to_vec();
        config.fsrs_parameters[0] *= 1.5;
        let changed = FeedService::new(repo.clone(), config, Arc::new(|| test_now() + Duration::days(1))).unwrap();
        assert_eq!(changed.next_page(&p, &query).await.unwrap(), page);
        let mut batch = examples::sample_feedback_batch();
        batch.session_id = page.session_id.clone();
        let mut exposure = event(&item.card.id, item.slot, 4_000, 1);
        exposure.delivery_id = item.delivery_id.clone();
        batch.events = vec![exposure.clone()];
        assert_eq!(changed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
        let provenance = exported_provenance(repo.as_ref(), &p, &item.card.id).await;
        let application = &provenance[0].1.application;
        assert_eq!(application.signal_thresholds.fast_swipe_ms, feed.cfg.signals.fast_swipe_ms);
        assert_eq!(application.scheduler_parameters, feed.fsrs.parameters());
        assert_eq!(application.desired_retention, feed.cfg.desired_retention);
        assert_eq!(application.issued_delivery, Some(original.attribution.clone()));
        assert_eq!(application.attribution_source, "issued_delivery_policy");
        assert_eq!(provenance[0].1.inferred_rating, feed.cfg.signals.interpret(&exposure).rating.map(|r| r as u8));
        assert_eq!(changed.record_feedback(&p, &batch).await.unwrap().duplicates, 1);
        // 改投递身份属于载荷冲突；同一投递可产生多个独立曝光事件。
        batch.events[0].delivery_id = Some("unknown".into());
        assert_eq!(changed.record_feedback(&p, &batch).await.unwrap().rejected[0].reason, "conflict");
        for variant in 0..8 {
            batch.events[0] = exposure.clone();
            batch.events[0].event_id = format!("bad-binding-{variant}");
            batch.session_id = page.session_id.clone();
            match variant {
                0 => batch.events[0].delivery_id = Some("unknown".into()),
                1 => batch.events[0].slot = 99,
                2 => batch.events[0].card_id = page.items[1].card.id.clone(),
                3 => batch.session_id = "wrong-session".into(),
                4 => {
                    batch.events[0].slot = 99;
                    batch.events[0].delivery_id = None;
                }
                5 => batch.session_id = "preview:non-learning".into(),
                6 => {
                    batch.session_id = "wrong-session".into();
                    batch.events[0].delivery_id = None;
                }
                _ => {
                    batch.session_id = "sess_0192f3a0".into();
                    batch.events[0].delivery_id = None;
                    batch.events[0].slot = 64;
                }
            }
            let ack = changed.record_feedback(&p, &batch).await.unwrap();
            assert_eq!((ack.accepted, ack.rejected.len()), (0, 1), "variant {variant}");
        }
        assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().unwrap().exposures, 1);
        let mut card = repo.get_card(&p.tenant_id, &item.card.id).await.unwrap().unwrap();
        card = repo
            .mutate_cards(
                &p.tenant_id,
                &[memoswish_core::content::CardMutation::Bgm {
                    id: card.id.clone(),
                    expected_revision: Some(card.revision),
                    binding: None,
                }],
            )
            .await
            .unwrap()
            .remove(0);
        batch.session_id = page.session_id.clone();
        batch.events = vec![exposure.clone()];
        batch.events[0].event_id = "second-exposure-legacy-client".into();
        // 旧客户端省略 ID 时按服务端的原 session/slot 恢复绑定。
        batch.events[0].delivery_id = None;
        assert_eq!(changed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
        let provenance = exported_provenance(repo.as_ref(), &p, &item.card.id).await;
        assert_eq!(provenance[1].1.revision_at_acceptance, card.revision);
        assert_eq!(provenance[1].1.application.issued_delivery, Some(original.attribution));
        assert_eq!(provenance[1].1.application.desired_retention, feed.cfg.desired_retention);
        let export = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
        assert_eq!(export["feed_deliveries"].as_array().unwrap().len(), 2);
        let before = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
        let preview =
            changed.next_page(&p, &FeedQuery { mode: Some("preview".into()), ..Default::default() }).await.unwrap();
        assert_eq!(preview.mode.as_deref(), Some("preview"));
        assert_eq!(preview.session_id, "preview:non-learning");
        assert!(preview.next_cursor.is_empty());
        assert!(preview.policy_version.is_none());
        assert!(preview.items.iter().all(|item| item.delivery_id.is_none()));
        assert_eq!(repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap(), before);
        repo.delete_card(&p.tenant_id, &card.id).await.unwrap();
        assert_eq!(changed.record_feedback(&p, &batch).await.unwrap().duplicates, 1);
        batch.events[0].event_id = "deleted-card".into();
        assert_eq!(changed.record_feedback(&p, &batch).await.unwrap().rejected[0].reason, "unknown card");
    }

    #[tokio::test]
    async fn sqlite_delivery_policy_and_binding() {
        delivery_policy_and_binding(Arc::new(SqliteRepository::in_memory().await.unwrap())).await;
    }

    #[tokio::test]
    async fn nonfinite_weights_cannot_issue_unrecoverable_policy() {
        let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
        for weight in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let cfg = FeedConfig { due_weight: weight, ..Default::default() };
            assert!(matches!(FeedService::new(repo.clone(), cfg, Arc::new(test_now)), Err(CoreError::Invalid(_))));
        }
        let cfg = FeedConfig { due_weight: f64::MAX, new_weight: f64::MAX, ..Default::default() };
        assert!(FeedService::new(repo, cfg, Arc::new(test_now)).is_err());
    }

    #[tokio::test]
    async fn injected_clock_public_boundaries() {
        use memoswish_core::repo::LearningDisposition::*;
        let (_, repo, p) = seeded(1).await;
        let time = Arc::new(std::sync::Mutex::new(test_now()));
        let clock = time.clone();
        let feed =
            FeedService::new(repo.clone(), FeedConfig::default(), Arc::new(move || *clock.lock().unwrap())).unwrap();
        let page = feed.next_page(&p, &FeedQuery::default()).await.unwrap();
        assert_eq!(page.generated_at, test_now());
        let item = &page.items[0];
        let mut batch = examples::sample_feedback_batch();
        batch.session_id = page.session_id;
        let mut e = event(&item.card.id, item.slot, 4_000, 1);
        e.delivery_id = item.delivery_id.clone();
        for (index, observed, received, disposition) in [
            (0, test_now() + Duration::nanoseconds(1), test_now(), FutureNotScheduled),
            (1, test_now() + Duration::nanoseconds(1), test_now() + Duration::nanoseconds(1), Scheduled),
            (2, test_now() - Duration::nanoseconds(1), test_now(), LateNotScheduled),
            (3, test_now(), test_now(), Scheduled),
        ] {
            *time.lock().unwrap() = received;
            e.event_id = format!("clock-{index}");
            e.shown_at = observed;
            batch.events = vec![e.clone()];
            assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
            let events = exported_provenance(repo.as_ref(), &p, &item.card.id).await;
            assert_eq!(events.last().unwrap().1.application.disposition, disposition);
            assert_eq!(events.last().unwrap().1.received_at, received);
        }
        let memory = repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().unwrap();
        assert_eq!((memory.reps, memory.exposures), (2, 4));
        *time.lock().unwrap() = memory.due.unwrap() - Duration::milliseconds(1);
        assert_eq!(feed.stats(&p).await.unwrap().due_cards, 0);
        *time.lock().unwrap() = memory.due.unwrap();
        assert_eq!(feed.stats(&p).await.unwrap().due_cards, 1);
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_delivery_policy_and_binding() {
        memoswish_storage::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = Arc::new(fixture.repository(4).await.unwrap());
            delivery_policy_and_binding(repo.clone()).await;
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }

    async fn seeded_in(repo: Arc<dyn Repository>, n: usize) -> (FeedService, Arc<dyn Repository>, Principal) {
        let p = Principal::local_owner("test");
        let deck = Deck { card_count: 0, ..examples::sample_deck() };
        seed_workspace(repo.as_ref(), &p, &deck).await;
        for i in 0..n {
            let mut c = examples::sample_card();
            c.id = format!("card-{i:03}");
            c.deck_id = deck.id.clone();
            c.front = CardFace { title: format!("word {i}"), ..Default::default() };
            repo.insert_card(&p.tenant_id, &c).await.unwrap();
        }
        // 旧策略测试使用升级前已发出的会话范围，不将未知会话当作历史证据。
        for id in ["sess_0192f3a0", "s1", "s-star", "s-easy", "s-hard"] {
            repo.save_session(&FeedSession {
                id: id.into(),
                tenant_id: p.tenant_id.clone(),
                user_id: p.user_id.clone(),
                next_slot: 64,
                recent_card_ids: vec![],
                created_at: test_now(),
                updated_at: test_now(),
            })
            .await
            .unwrap();
        }
        (FeedService::new(repo.clone(), FeedConfig::default(), Arc::new(test_now)).unwrap(), repo, p)
    }

    fn event(card_id: &str, slot: u64, dwell: u32, loops: u32) -> ImplicitFeedback {
        ImplicitFeedback {
            delivery_id: None,
            event_id: format!("ev-{card_id}-{slot}"),
            card_id: card_id.into(),
            slot,

            shown_at: test_now() - Duration::seconds(5),
            dwell_time_ms: dwell,
            loop_count: loops,
            swipe_velocity: 1.0,
            swipe_direction: SwipeDirection::Next,
            flipped: false,
            double_tapped: false,
            long_pressed: false,
            muted: false,
        }
    }

    async fn deleted_content_is_excluded_from_live_learning(repo: Arc<dyn Repository>) {
        let (feed, repo, p) = seeded_in(repo, 3).await;
        let mut batch = examples::sample_feedback_batch();
        let mut learned = event("card-000", 0, 4_000, 1);
        learned.double_tapped = true;
        batch.events = vec![learned];
        feed.record_feedback(&p, &batch).await.unwrap();
        let mut exposure = event("card-001", 1, 200_000, 0);
        exposure.double_tapped = true;
        batch.events = vec![exposure];
        feed.record_feedback(&p, &batch).await.unwrap();
        let archived = repo.get_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap().unwrap();
        assert_eq!(archived.reps, 0);
        assert!(archived.starred);
        let original = feed.stats(&p).await.unwrap();
        assert_eq!(original.starred_cards, 2);
        repo.delete_card(&p.tenant_id, "card-001").await.unwrap();
        let stats = feed.stats(&p).await.unwrap();
        assert_eq!((stats.total_cards, stats.seen_cards, stats.starred_cards, stats.total_exposures), (2, 1, 1, 1));
        assert_eq!(feed.list_starred_cards(&p, None).await.unwrap().len(), 1);
        let card = repo.get_card(&p.tenant_id, "card-000").await.unwrap().unwrap();
        let deck_stats = feed.stats_for_deck(&p, Some(&card.deck_id)).await.unwrap();
        assert_eq!(deck_stats.total_exposures, 1);
        assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap(), Some(archived));
        repo.delete_deck(&p.tenant_id, &card.deck_id).await.unwrap();
        let stats = feed.stats(&p).await.unwrap();
        assert_eq!(
            (stats.total_cards, stats.seen_cards, stats.due_cards, stats.starred_cards, stats.total_exposures),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(stats.average_retrievability, 0.0);
        let deck_stats = feed.stats_for_deck(&p, Some(&card.deck_id)).await.unwrap();
        assert_eq!((deck_stats.seen_cards, deck_stats.starred_cards, deck_stats.total_exposures), (0, 0, 0));
        assert!(feed.list_starred_cards(&p, None).await.unwrap().is_empty());
        assert!(feed.list_starred_cards(&p, Some(&card.deck_id)).await.unwrap().is_empty());
        assert_eq!(feed.recommended_retention(&p).await.unwrap(), FeedConfig::default().desired_retention as f32);
        assert!(repo.get_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap().is_some());
    }

    async fn deleted_content_receipts_replay_without_reviving_live_learning(repo: Arc<dyn Repository>) {
        let (feed, repo, p) = seeded_in(repo, 2).await;
        let query = FeedQuery { request_id: Some("before-delete".into()), limit: Some(2), ..Default::default() };
        let page = feed.next_page(&p, &query).await.unwrap();
        let deleted = &page.items[0];
        let mut batch = examples::sample_feedback_batch();
        batch.session_id = page.session_id.clone();
        let mut learned = event(&deleted.card.id, deleted.slot, 4_000, 1);
        learned.double_tapped = true;
        batch.events = vec![learned];
        assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
        let memory = repo.get_memory(&p.tenant_id, &p.user_id, &deleted.card.id).await.unwrap().unwrap();
        repo.delete_card(&p.tenant_id, &deleted.card.id).await.unwrap();
        assert_eq!(feed.next_page(&p, &query).await.unwrap(), page);
        assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().duplicates, 1);
        batch.events[0].event_id.push_str("-new");
        let rejected = feed.record_feedback(&p, &batch).await.unwrap();
        assert_eq!((rejected.accepted, rejected.duplicates), (0, 0));
        assert_eq!(rejected.rejected[0].reason, "unknown card");
        assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, &deleted.card.id).await.unwrap(), Some(memory));
        assert!(repo.list_memory(&p.tenant_id, &p.user_id).await.unwrap().is_empty());
        assert!(repo.insert_card(&p.tenant_id, &deleted.card).await.is_err());
        let next = FeedQuery {
            session_id: Some(page.session_id.clone()),
            cursor: Some(page.next_cursor.clone()),
            limit: Some(2),
            ..Default::default()
        };
        let successor = feed.next_page(&p, &next).await.unwrap();
        assert!(!successor.items.is_empty());
        assert!(successor.items.iter().all(|item| item.card.id != deleted.card.id));
        repo.delete_deck(&p.tenant_id, &deleted.card.deck_id).await.unwrap();
        assert_eq!(feed.next_page(&p, &query).await.unwrap(), page);
        assert_eq!(feed.next_page(&p, &next).await.unwrap(), successor);
        let empty = feed
            .next_page(&p, &FeedQuery { request_id: Some("after-delete".into()), limit: Some(2), ..Default::default() })
            .await
            .unwrap();
        assert!(empty.items.is_empty());
        assert!(empty.prefetch.entries.is_empty());
        assert_eq!(feed.stats(&p).await.unwrap().total_exposures, 0);
        assert!(feed.list_starred_cards(&p, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sqlite_deleted_content_live_learning() {
        deleted_content_is_excluded_from_live_learning(Arc::new(SqliteRepository::in_memory().await.unwrap())).await;
        deleted_content_receipts_replay_without_reviving_live_learning(Arc::new(
            SqliteRepository::in_memory().await.unwrap(),
        ))
        .await;
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_deleted_content_live_learning() {
        memoswish_storage::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let repo = fixture.repository(8).await.unwrap();
            deleted_content_is_excluded_from_live_learning(Arc::new(repo)).await;
            fixture.cleanup().await;
            let fixture = test.fixture(&url).await;
            let repo = fixture.repository(8).await.unwrap();
            deleted_content_receipts_replay_without_reviving_live_learning(Arc::new(repo)).await;
            fixture.cleanup().await;
        });
    }

    #[tokio::test]
    async fn identified_pages_replay_after_content_feedback_and_config_changes() {
        let (feed, repo, p) = seeded(8).await;
        let q = FeedQuery { request_id: Some("stable-first".into()), ..Default::default() };
        let first = feed.next_page(&p, &q).await.unwrap();
        let mut batch = examples::sample_feedback_batch();
        batch.session_id = first.session_id.clone();
        batch.events.truncate(1);
        batch.events[0].card_id = first.items[0].card.id.clone();
        batch.events[0].slot = first.items[0].slot;
        assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
        let card = &first.items[0].card;
        repo.mutate_cards(
            &p.tenant_id,
            &[memoswish_core::content::CardMutation::Bgm {
                id: card.id.clone(),
                expected_revision: Some(card.revision),
                binding: None,
            }],
        )
        .await
        .unwrap();
        let changed = FeedService::new(
            repo.clone(),
            FeedConfig { default_page: 2, window_after: 1, ..Default::default() },
            Arc::new(test_now),
        )
        .unwrap();
        assert_eq!(changed.next_page(&p, &q).await.unwrap(), first);
        let next = FeedQuery {
            session_id: Some(first.session_id.clone()),
            cursor: Some(first.next_cursor.clone()),
            ..Default::default()
        };
        let second = changed.next_page(&p, &next).await.unwrap();
        assert_eq!(second.items[0].slot, first.items.len() as u64);
        assert_eq!(feed.next_page(&p, &next).await.unwrap(), second);
        let (left, right) = tokio::join!(feed.next_page(&p, &next), changed.next_page(&p, &next));
        assert_eq!(left.unwrap(), right.unwrap());
        assert_eq!(changed.next_page(&p, &q).await.unwrap(), first);
    }

    #[tokio::test]
    async fn legacy_cursorless_queries_preserve_session_selection() {
        let (feed, _, p) = seeded(1).await;
        for id in ["", "legacy:用户", &"x".repeat(80)] {
            let q = FeedQuery { session_id: Some(id.into()), limit: Some(1), ..Default::default() };
            let first = feed.next_page(&p, &q).await.unwrap();
            if !id.is_empty() && id.len() <= 64 {
                assert_eq!(first.session_id, id);
            } else {
                assert!(first.session_id.starts_with("sess_"));
            }
            let next = feed
                .next_page(&p, &FeedQuery { session_id: Some(first.session_id), limit: Some(2), ..Default::default() })
                .await
                .unwrap();
            assert_eq!(next.items[0].slot, 1);
        }
    }

    #[tokio::test]
    async fn concurrent_identified_first_pages_share_one_issuance() {
        let (feed, repo, p) = seeded(3).await;
        let q = FeedQuery { request_id: Some("concurrent-first".into()), limit: Some(2), ..Default::default() };
        let barrier = tokio::sync::Barrier::new(2);
        let (left, right) = tokio::join!(
            async {
                barrier.wait().await;
                feed.next_page(&p, &q).await.unwrap()
            },
            async {
                barrier.wait().await;
                feed.next_page(&p, &q).await.unwrap()
            },
        );
        assert_eq!(left, right);
        assert_eq!(repo.get_session(&p.tenant_id, &p.user_id, &left.session_id).await.unwrap().unwrap().next_slot, 2);
    }

    #[tokio::test]
    async fn pages_are_continuous_and_deduplicated() {
        let (feed, _repo, p) = seeded(30).await;
        let p1 = feed.next_page(&p, &FeedQuery { limit: Some(10), ..Default::default() }).await.unwrap();
        assert_eq!(p1.items.len(), 4);
        assert_eq!(p1.items[0].slot, 0);
        assert!(p1.items.iter().all(|i| i.reason == FeedReason::New));
        assert_eq!(p1.prefetch.entries.len(), 4);
        assert_eq!(p1.prefetch.window_after, 5);
        let p2 = feed
            .next_page(
                &p,
                &FeedQuery {
                    session_id: Some(p1.session_id.clone()),
                    cursor: Some(p1.next_cursor.clone()),
                    limit: Some(10),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(p2.session_id, p1.session_id);
        assert_eq!(p2.items[0].slot, 4);
        let ids1: HashSet<_> = p1.items.iter().map(|i| &i.card.id).collect();
        assert!(p2.items.iter().all(|i| !ids1.contains(&i.card.id)));
    }

    #[tokio::test]
    async fn small_deck_returns_partial_pages_without_repetition() {
        for count in [0, 1, 2, 3, 5] {
            let (feed, _repo, p) = seeded(count).await;
            let mut session = None;
            let mut next_slot = 0;
            for _ in 0..5 {
                let page = feed
                    .next_page(&p, &FeedQuery { session_id: session.clone(), limit: Some(7), ..Default::default() })
                    .await
                    .unwrap();
                assert_eq!(page.items.len(), count.min(4));
                assert_eq!(page.items.iter().map(|item| &item.card.id).collect::<HashSet<_>>().len(), page.items.len());
                for item in &page.items {
                    assert_eq!(item.slot, next_slot);
                    next_slot += 1;
                }
                session = Some(page.session_id);
            }
        }
    }

    #[tokio::test]
    async fn feedback_updates_memory_idempotently() {
        let (feed, repo, p) = seeded(5).await;
        let batch = FeedbackBatch {
            session_id: "s1".into(),
            client_id: "c1".into(),

            sent_at: test_now(),
            events: vec![event("card-000", 0, 800, 0), event("card-001", 1, 5_000, 3), event("missing", 2, 1_000, 0)],
        };
        let ack = feed.record_feedback(&p, &batch).await.unwrap();
        assert_eq!((ack.accepted, ack.duplicates, ack.rejected.len()), (2, 0, 1));
        let again = feed.record_feedback(&p, &batch).await.unwrap();
        assert_eq!((again.accepted, again.duplicates), (0, 2));

        let easy = repo.get_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap().unwrap();
        let hard = repo.get_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap().unwrap();
        assert_eq!(easy.last_rating, Some(Rating::Easy as u8));
        assert!(hard.starred);
        assert!(easy.stability > hard.stability);
        assert_eq!(easy.exposures, 1);

        let stats = feed.stats(&p).await.unwrap();
        assert_eq!((stats.total_cards, stats.seen_cards, stats.starred_cards), (5, 2, 1));
    }

    #[tokio::test]
    async fn double_tap_adds_card_to_starred_list() {
        let (feed, _repo, p) = seeded(4).await;
        assert!(feed.list_starred_cards(&p, None).await.unwrap().is_empty());

        let mut ev1 = event("card-002", 0, 1_800, 1);
        ev1.double_tapped = true;

        {
            ev1.shown_at = test_now() - Duration::seconds(20);
        }
        let mut ev2 = event("card-001", 1, 2_000, 1);
        ev2.double_tapped = true;

        {
            ev2.shown_at = test_now() - Duration::seconds(5);
        }

        let batch = FeedbackBatch {
            session_id: "s-star".into(),
            client_id: "c1".into(),

            sent_at: test_now(),
            events: vec![ev1, ev2],
        };
        let ack = feed.record_feedback(&p, &batch).await.unwrap();
        assert_eq!(ack.accepted, 2);

        let starred = feed.list_starred_cards(&p, None).await.unwrap();
        assert_eq!(starred.len(), 2);
        // 按最近复习时间倒序排列：card-001 晚于 card-002。
        assert_eq!(starred[0].id, "card-001");
        assert_eq!(starred[1].id, "card-002");
    }

    #[tokio::test]
    async fn theme_continuity_groups_matching_bgm_themes() {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let p = Principal::local_owner("test");
        let deck = Deck { card_count: 0, ..examples::sample_deck() };
        seed_workspace(repo.as_ref(), &p, &deck).await;

        // 交替写入 calm 与 upbeat 两种 BGM 主题的卡片。
        for i in 0..6 {
            let mut c = examples::sample_card();
            c.id = format!("card-{i:03}");
            c.deck_id = deck.id.clone();
            c.front = CardFace { title: format!("concept {i}"), ..Default::default() };
            if let Some(bgm) = &mut c.bgm {
                bgm.theme_key = if i % 2 == 0 { "theme-calm".into() } else { "theme-upbeat".into() };
            }
            repo.insert_card(&p.tenant_id, &c).await.unwrap();
        }

        let feed = FeedService::new(repo, FeedConfig::default(), Arc::new(test_now)).unwrap();
        let page = feed.next_page(&p, &FeedQuery { limit: Some(6), ..Default::default() }).await.unwrap();
        assert_eq!(page.items.len(), 4);

        // 公平首位后保留主题连续性；新卡预算使本页止于第四张。
        let themes: Vec<&str> = page.items.iter().map(|it| it.card.bgm.as_ref().unwrap().theme_key.as_str()).collect();
        assert_eq!(themes, vec!["theme-calm", "theme-calm", "theme-calm", "theme-upbeat"]);
    }

    #[tokio::test]
    async fn recommended_retention_adapts_to_learner_memory() {
        let (feed, _repo, p) = seeded(8).await;
        // 复习不足 5 张时返回默认保持率 0.90。
        let initial = feed.recommended_retention(&p).await.unwrap();
        assert!((initial - 0.90).abs() < 1e-4);

        // 连续 6 张卡片快速划走（Easy 评分，稳定性高、难度低、无遗忘），推荐保持率应高于默认值。
        let easy_events: Vec<_> = (0..6).map(|i| event(&format!("card-{i:03}"), i, 800, 0)).collect();
        feed.record_feedback(
            &p,
            &FeedbackBatch {
                session_id: "s-easy".into(),
                client_id: "c1".into(),

                sent_at: test_now(),
                events: easy_events,
            },
        )
        .await
        .unwrap();
        let high_mastery = feed.recommended_retention(&p).await.unwrap();
        assert!((0.80..=0.95).contains(&high_mastery));
        assert!(high_mastery > initial, "expected {high_mastery} > {initial}");

        // 随后多次长时间停留且循环多次（Again 评分，产生遗忘并推高难度），推荐保持率应下调。
        let hard_events: Vec<_> = (0..6)
            .map(|i| {
                let mut ev = event(&format!("card-{i:03}"), 10 + i, 9_000, 4);
                ev.flipped = true;
                ev
            })
            .collect();
        feed.record_feedback(
            &p,
            &FeedbackBatch {
                session_id: "s-hard".into(),
                client_id: "c1".into(),

                sent_at: test_now(),
                events: hard_events,
            },
        )
        .await
        .unwrap();
        let struggling = feed.recommended_retention(&p).await.unwrap();
        assert!((0.80..=0.95).contains(&struggling));
        assert!(struggling < high_mastery, "expected {struggling} < {high_mastery}");
    }

    // 学习夹具建立真实成员，共同复用生产开户事务和已有卡组写入入口。
    async fn seed_workspace(repo: &dyn Repository, p: &Principal, deck: &Deck) {
        repo.upsert_tenant(&memoswish_core::repo::TenantRecord {
            id: p.tenant_id.clone(),
            name: "Test".into(),
            plan: "free".into(),
            created_at: deck.created_at,
        })
        .await
        .unwrap();
        repo.insert_user(&memoswish_core::repo::UserRecord {
            id: p.user_id.clone(),
            tenant_id: p.tenant_id.clone(),
            email: "feed@example.com".into(),
            display_name: "Learner".into(),
            password_hash: String::new(),
            role: memoswish_core::Role::Owner,
            created_at: deck.created_at,
        })
        .await
        .unwrap();
        repo.insert_deck(&p.tenant_id, deck).await.unwrap();
    }
    #[tokio::test]
    async fn feedback_retry_budget_and_permanent_errors() {
        let attempts = std::cell::Cell::new(0);
        let error = retry_learning(|| {
            attempts.set(attempts.get() + 1);
            std::future::ready(Ok(LearningEventOutcome::Retry))
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.get(), TRANSACTION_ATTEMPTS);
        assert_eq!(error.http_status(), 503);
        assert_eq!(error.code(), "temporarily_unavailable");
        attempts.set(0);
        let error = retry_learning(|| {
            attempts.set(attempts.get() + 1);
            std::future::ready(Err(CoreError::internal("permanent SQL failure")))
        })
        .await
        .unwrap_err();
        assert_eq!(attempts.get(), 1);
        assert_eq!(error.http_status(), 500);
    }

    #[tokio::test]
    async fn feedback_idle_exposure_and_favorite_are_idempotent() {
        let (feed, repo, p) = seeded(3).await;
        let mut batch = examples::sample_feedback_batch();
        let mut idle = batch.events[0].clone();
        idle.card_id = "card-002".into();
        idle.event_id.push('i');
        idle.dwell_time_ms = feed.cfg.signals.idle_ms + 1;
        idle.double_tapped = true;
        batch.events = vec![idle];
        assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
        let memory = repo.get_memory(&p.tenant_id, &p.user_id, "card-002").await.unwrap().unwrap();
        assert_eq!((memory.exposures, memory.reps, memory.starred), (1, 0, true));
        assert!(memory.last_review.is_none());
        assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().duplicates, 1);
    }

    async fn sqlite_concurrent_feedback(existing: bool) {
        let path = std::env::temp_dir().join(format!("memoswish-s9-fsrs-{}.db", new_id()));
        let backend = Arc::new(SqliteRepository::connect(&format!("sqlite://{}", path.display())).await.unwrap());
        concurrent_feedback_matches_serial_fsrs_transitions(backend.clone(), existing, false).await;
        backend.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn sqlite_concurrent_feedback_from_absence() {
        sqlite_concurrent_feedback(false).await;
    }

    #[tokio::test]
    async fn sqlite_concurrent_feedback_from_existing_memory() {
        sqlite_concurrent_feedback(true).await;
    }

    fn postgres_concurrent_feedback(existing: bool) {
        memoswish_storage::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let backend = Arc::new(fixture.repository(4).await.unwrap());
            concurrent_feedback_matches_serial_fsrs_transitions(backend.clone(), existing, false).await;
            backend.pool().close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_concurrent_feedback_from_absence() {
        postgres_concurrent_feedback(false);
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_concurrent_feedback_from_existing_memory() {
        postgres_concurrent_feedback(true);
    }

    async fn concurrent_feedback_matches_serial_fsrs_transitions(
        backend: Arc<dyn Repository>,
        existing: bool,
        late: bool,
    ) {
        let (feed, repo, p) = seeded_in(backend, 2).await;
        let mut a = examples::sample_feedback_batch();
        a.events = vec![event("card-000", 0, 800, 0)];
        a.events[0].shown_at -= Duration::days(1);
        // SQLite 以毫秒保存时间，让双后端采用相同的精确事件瞬间。
        a.events[0].shown_at = DateTime::from_timestamp_millis(a.events[0].shown_at.timestamp_millis()).unwrap();
        let mut b = a.clone();
        b.events[0].event_id.push('b');
        b.events[0].dwell_time_ms = 9_000;
        b.events[0].loop_count = 4;
        b.events[0].long_pressed = true;
        b.events[0].shown_at += Duration::hours(if late { -12 } else { 12 });
        let now = a.events[0].shown_at + Duration::days(4);

        if existing {
            let mut initial = a.clone();
            initial.events[0].shown_at -= Duration::days(1);
            initial.events[0].event_id.push('i');
            for card_id in ["card-000", "card-001"] {
                initial.events[0].card_id = card_id.into();
                initial.events[0].event_id = format!("initial-{card_id}");
                assert_eq!(feed.record_feedback_at(&p, &initial, now).await.unwrap().accepted, 1);
            }
        }
        let baseline = repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap();
        assert_eq!(baseline.is_some(), existing);
        let left_gate = FeedbackGate::new();
        let right_gate = FeedbackGate::new();
        let start = |batch: FeedbackBatch, gate: Arc<FeedbackGate>| {
            let mut request_feed = feed.clone();
            request_feed.feedback_gate = Some(gate);
            let principal = p.clone();
            tokio::spawn(async move { request_feed.record_feedback_at(&principal, &batch, now).await })
        };
        let left = start(a.clone(), left_gate.clone());
        let right = start(b.clone(), right_gate.clone());
        tokio::join!(left_gate.reached.notified(), right_gate.reached.notified());
        assert_eq!(*left_gate.snapshots.lock().unwrap(), vec![baseline.clone()]);
        assert_eq!(*right_gate.snapshots.lock().unwrap(), vec![baseline.clone()]);

        // 两次实际读取均已完成后先让 A 提交，再让 B 以旧版本进入真实 CAS。
        left_gate.resume.add_permits(1);
        let left_ack = left.await.unwrap().unwrap();
        assert_eq!((left_ack.accepted, left_ack.duplicates, left_ack.rejected.len()), (1, 0, 0));
        let winner = repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap();
        right_gate.resume.add_permits(1);
        let right_ack = right.await.unwrap().unwrap();
        assert_eq!((right_ack.accepted, right_ack.duplicates, right_ack.rejected.len()), (1, 0, 0));
        assert_eq!(*left_gate.outcomes.lock().unwrap(), vec![LearningEventOutcome::Applied]);
        assert_eq!(
            *right_gate.outcomes.lock().unwrap(),
            vec![LearningEventOutcome::Retry, LearningEventOutcome::Applied]
        );
        assert_eq!(*right_gate.snapshots.lock().unwrap(), vec![baseline, winner]);

        // 对照相同初态、相同事件与确定的 A→B 提交次序，比较全部记忆字段及内部版本。
        for batch in [&a, &b] {
            let mut serial_batch = batch.clone();
            serial_batch.events[0].card_id = "card-001".into();
            serial_batch.events[0].event_id.push('s');
            assert_eq!(feed.record_feedback_at(&p, &serial_batch, now).await.unwrap().accepted, 1);
        }
        let actual = repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap().unwrap();
        let mut serial = repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap().unwrap();
        serial.state.card_id = actual.state.card_id.clone();
        assert_eq!(actual, serial, "CAS retry must recompute every FSRS field from the committed snapshot");
        let expected_count = 2 + u32::from(existing);
        assert_eq!((actual.state.exposures, actual.state.reps), (expected_count, expected_count - u32::from(late)));
        assert_eq!(actual.state.lapses, u32::from(!late));
        let actual_provenance = exported_provenance(repo.as_ref(), &p, "card-000").await;
        let serial_provenance = exported_provenance(repo.as_ref(), &p, "card-001").await;
        assert_eq!(
            actual_provenance.iter().map(|(_, p)| p).collect::<Vec<_>>(),
            serial_provenance.iter().map(|(_, p)| p).collect::<Vec<_>>()
        );
        assert_eq!(
            actual_provenance.last().unwrap().1.application.disposition,
            if late {
                memoswish_core::repo::LearningDisposition::LateNotScheduled
            } else {
                memoswish_core::repo::LearningDisposition::Scheduled
            }
        );
        assert!(actual.state.starred);
        for batch in [&a, &b] {
            let ack = feed.record_feedback_at(&p, batch, now).await.unwrap();
            assert_eq!((ack.accepted, ack.duplicates, ack.rejected.len()), (0, 1, 0));
        }
        assert_eq!(repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap().unwrap(), actual);
    }

    #[tokio::test]
    async fn sqlite_late_cas_loser_recomputes_disposition() {
        for existing in [false, true] {
            concurrent_feedback_matches_serial_fsrs_transitions(
                Arc::new(SqliteRepository::in_memory().await.unwrap()),
                existing,
                true,
            )
            .await;
        }
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_late_cas_loser_recomputes_disposition() {
        memoswish_storage::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            for existing in [false, true] {
                let fixture = test.fixture(&url).await;
                let backend = Arc::new(fixture.repository(4).await.unwrap());
                concurrent_feedback_matches_serial_fsrs_transitions(backend.clone(), existing, true).await;
                backend.pool().close().await;
                fixture.cleanup().await;
            }
        });
    }

    async fn exported_provenance(
        repo: &dyn Repository,
        p: &Principal,
        card: &str,
    ) -> Vec<(String, memoswish_core::repo::LearningEventProvenance)> {
        let export = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
        let mut events: Vec<_> = export["feedback_events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["body"]["card_id"].as_str() == Some(card))
            .map(|row| {
                (
                    row["body"]["event_id"].as_str().unwrap().to_owned(),
                    memoswish_core::repo::LearningEventProvenance::deserialize(&row["application_provenance"]).unwrap(),
                )
            })
            .collect();
        events.sort_by_key(|(_, event)| event.successor_version);
        events
    }

    #[tokio::test]
    async fn sqlite_event_disposition_and_policy_provenance() {
        let path = std::env::temp_dir().join(format!("memoswish-s10-restart-{}.db", new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = Arc::new(SqliteRepository::connect(&url).await.unwrap());
        let receipt = event_disposition_and_policy_provenance(repo.clone()).await;
        repo.pool().close().await;
        let reopened = Arc::new(SqliteRepository::connect(&url).await.unwrap());
        assert_restarted_receipt(reopened.clone(), receipt).await;
        reopened.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_event_disposition_and_policy_provenance() {
        memoswish_storage::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = Arc::new(fixture.repository(4).await.unwrap());
            let receipt = event_disposition_and_policy_provenance(repo.clone()).await;
            repo.pool().close().await;
            let reopened = Arc::new(fixture.repository(4).await.unwrap());
            assert_restarted_receipt(reopened.clone(), receipt).await;
            reopened.pool().close().await;
            fixture.cleanup().await;
        });
    }

    struct RestartReceipt {
        batches: Vec<FeedbackBatch>,
        memory: VersionedMemory,
        provenance: Vec<(String, memoswish_core::repo::LearningEventProvenance)>,
    }

    async fn assert_restarted_receipt(repo: Arc<dyn Repository>, receipt: RestartReceipt) {
        let p = Principal::local_owner("test");
        let feed = FeedService::new(
            repo.clone(),
            FeedConfig { desired_retention: 0.85, ..Default::default() },
            Arc::new(test_now),
        )
        .unwrap();
        for now in ["2026-11-08T12:00:00Z", "2026-10-01T12:00:00Z"] {
            for batch in &receipt.batches {
                let ack = feed.record_feedback_at(&p, batch, now.parse().unwrap()).await.unwrap();
                assert_eq!((ack.accepted, ack.duplicates, ack.rejected.len()), (0, 1, 0));
            }
            assert_eq!(
                repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-004").await.unwrap().unwrap(),
                receipt.memory
            );
            assert_eq!(exported_provenance(repo.as_ref(), &p, "card-004").await, receipt.provenance);
        }
    }

    async fn event_disposition_and_policy_provenance(backend: Arc<dyn Repository>) -> RestartReceipt {
        use memoswish_core::repo::LearningDisposition::*;
        let (feed, repo, p) = seeded_in(backend, 5).await;
        let now: DateTime<Utc> = "2026-11-07T12:00:00Z".parse().unwrap();
        let old = now - Duration::days(20) + Duration::nanoseconds(123_456_789);
        let mut batch = examples::sample_feedback_batch();
        let mut first = event("card-000", 0, 4_000, 1);
        first.event_id = "first".into();
        first.shown_at = old;
        let mut second = first.clone();
        second.event_id = "second".into();
        second.shown_at += Duration::days(2);
        second.double_tapped = true;
        batch.events = vec![second.clone(), first.clone()];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 2);
        let ordered = repo.get_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap().unwrap();
        assert_eq!((ordered.reps, ordered.exposures), (2, 2));
        assert_eq!(ordered.last_review.unwrap().timestamp_millis(), second.shown_at.timestamp_millis());
        let provenance = exported_provenance(repo.as_ref(), &p, "card-000").await;
        assert_eq!(provenance[0].1.observed_at, old);
        assert_eq!(provenance[0].1.received_at, now);
        assert_eq!(provenance[0].1.application.scheduler_parameters, fsrs::DEFAULT_PARAMETERS);
        assert_eq!(provenance[0].1.predecessor_version, None);
        assert_eq!(provenance[1].1.predecessor_version, Some(1));
        assert_eq!(provenance[1].1.successor_version, 2);
        assert_eq!(provenance[0].1.revision_at_acceptance, examples::sample_card().revision);
        assert!(provenance.iter().all(|(_, e)| e.application.disposition == Scheduled));

        // 跨批次倒序接受保留晚到收藏与曝光，但全部调度字段保持第二条之后的值。
        second.card_id = "card-001".into();
        second.event_id = "second-reversed".into();
        first.event_id = "first-reversed".into();
        second.double_tapped = false;
        first.card_id = second.card_id.clone();
        first.double_tapped = true;
        batch.events = vec![second.clone()];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        let before = repo.get_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap().unwrap();
        batch.events = vec![first.clone()];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        let mut expected = before.clone();
        expected.exposures += 1;
        expected.starred = true;
        assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap().unwrap(), expected);
        let events = exported_provenance(repo.as_ref(), &p, "card-001").await;
        assert_eq!(events[1].1.application.disposition, LateNotScheduled);
        assert_eq!(events[1].1.application.effective_at, None);
        assert!(events[1].1.application.star);

        // 未来纳秒仍保留原始身份；时钟追上及配置改变后重试不能重新分类。
        let mut future = first.clone();
        future.event_id = "future".into();
        future.shown_at = now + Duration::nanoseconds(1);
        batch.events = vec![future.clone()];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        let future_provenance = exported_provenance(repo.as_ref(), &p, "card-001").await;
        assert_eq!(future_provenance[2].1.application.disposition, FutureNotScheduled);
        assert_eq!(future_provenance[2].1.observed_at, future.shown_at);
        let mut config = FeedConfig {
            desired_retention: 0.8,
            fsrs_parameters: fsrs::DEFAULT_PARAMETERS.to_vec(),
            ..Default::default()
        };
        config.signals.fast_swipe_ms = 5_000;
        config.fsrs_parameters[0] *= 1.1;
        let restarted = FeedService::new(repo.clone(), config.clone(), Arc::new(test_now)).unwrap();
        assert_eq!(restarted.record_feedback_at(&p, &batch, now + Duration::days(1)).await.unwrap().duplicates, 1);
        assert_eq!(exported_provenance(repo.as_ref(), &p, "card-001").await, future_provenance);
        let mut idle = first.clone();
        idle.event_id = "idle".into();
        idle.dwell_time_ms = 200_000;
        idle.shown_at = now;
        batch.events = vec![idle];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        expected.exposures += 2;
        assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, "card-001").await.unwrap().unwrap(), expected);
        assert_eq!(exported_provenance(repo.as_ref(), &p, "card-001").await[3].1.application.disposition, NotRated);
        batch.events[0].event_id = "new-policy".into();
        batch.events[0].dwell_time_ms = 4_000;
        assert_eq!(restarted.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        let changed = exported_provenance(repo.as_ref(), &p, "card-001").await;
        assert_eq!(changed[4].1.application.signal_thresholds.fast_swipe_ms, 5_000);
        assert_eq!(changed[4].1.application.scheduler_parameters, config.fsrs_parameters);
        assert_eq!(changed[4].1.application.desired_retention, 0.8);
        assert_ne!(changed[4].1.application.scheduler_parameters, changed[0].1.application.scheduler_parameters);

        // 相同毫秒内按原始纳秒及事件 ID 排序，等时事件是零日复习。
        let mut a = first.clone();
        a.card_id = "card-002".into();
        a.event_id = "a".into();
        a.shown_at = old;
        a.long_pressed = true;
        let mut z = a.clone();
        z.event_id = "z".into();
        z.long_pressed = false;
        batch.events = vec![z.clone(), a.clone()];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 2);
        let tied = exported_provenance(repo.as_ref(), &p, "card-002").await;
        assert_eq!(tied.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), vec!["a", "z"]);
        assert_eq!(tied[0].1.application.effective_at, tied[1].1.application.effective_at);
        for mut e in [a, z] {
            e.card_id = "card-003".into();
            e.event_id.push_str("-serial");
            batch.events = vec![e];
            feed.record_feedback_at(&p, &batch, now).await.unwrap();
        }
        let actual = repo.get_memory(&p.tenant_id, &p.user_id, "card-002").await.unwrap().unwrap();
        let mut serial = repo.get_memory(&p.tenant_id, &p.user_id, "card-003").await.unwrap().unwrap();
        serial.card_id = actual.card_id.clone();
        assert_eq!(actual, serial);

        // 首次未来观察不能污染后续离线调度，未来之前也没有七日下界替换。
        future.card_id = "card-004".into();
        future.event_id = "future-first".into();
        batch.events = vec![future];
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        let unreviewed = repo.get_memory(&p.tenant_id, &p.user_id, "card-004").await.unwrap().unwrap();
        assert_eq!((unreviewed.reps, unreviewed.exposures, unreviewed.last_review, unreviewed.due), (0, 1, None, None));
        batch.events[0].event_id = "offline-after-future".into();
        batch.events[0].shown_at = old;
        assert_eq!(feed.record_feedback_at(&p, &batch, now).await.unwrap().accepted, 1);
        let recovered = repo.get_memory(&p.tenant_id, &p.user_id, "card-004").await.unwrap().unwrap();
        assert_eq!(recovered.last_review.unwrap().timestamp_millis(), old.timestamp_millis());

        // 有限越界配置经过上游裁剪；持久凭据与导出保存实际模型参数。
        let mut clipped_config =
            FeedConfig { fsrs_parameters: fsrs::DEFAULT_PARAMETERS.to_vec(), ..Default::default() };
        clipped_config.fsrs_parameters[4] = 100.0;
        let clipped_feed = FeedService::new(repo.clone(), clipped_config.clone(), Arc::new(test_now)).unwrap();
        let mut clipped_batch = examples::sample_feedback_batch();
        let mut clipped = event("card-004", 0, 4_000, 1);
        clipped.event_id = "clipped-policy".into();
        clipped.shown_at = now;
        clipped_batch.events = vec![clipped];
        assert_eq!(clipped_feed.record_feedback_at(&p, &clipped_batch, now).await.unwrap().accepted, 1);
        let clipped_provenance = exported_provenance(repo.as_ref(), &p, "card-004").await;
        let application = &clipped_provenance[2].1.application;
        let mut effective = fsrs::DEFAULT_PARAMETERS.to_vec();
        effective[4] = 10.0;
        assert_eq!(application.disposition, Scheduled);
        assert_eq!(application.scheduler_parameters, effective);
        assert_ne!(application.scheduler_parameters, clipped_config.fsrs_parameters);
        assert_eq!(application.scheduler_adapter_version, "learntok-fsrs-v2");
        let scheduled = repo.get_memory(&p.tenant_id, &p.user_id, "card-004").await.unwrap().unwrap();
        let replayed = Fsrs::new(&application.scheduler_parameters, application.desired_retention)
            .unwrap()
            .review(
                Some(Memory { stability: recovered.stability, difficulty: recovered.difficulty }),
                (now - recovered.last_review.unwrap()).num_milliseconds() as f64 / 86_400_000.0,
                Rating::from_u8(clipped_provenance[2].1.inferred_rating.unwrap()).unwrap(),
            )
            .unwrap();
        assert_eq!(scheduled.stability, replayed.memory.stability);
        assert_eq!(scheduled.difficulty, replayed.memory.difficulty);
        assert_eq!(clipped_feed.record_feedback_at(&p, &clipped_batch, now).await.unwrap().duplicates, 1);
        assert_eq!(exported_provenance(repo.as_ref(), &p, "card-004").await, clipped_provenance);

        // 导出仍按 tenant/user 过滤，不把当前策略写进其他用户或历史未知记录。
        let mut peer = p.clone();
        peer.user_id = "peer".into();
        repo.insert_user(&memoswish_core::repo::UserRecord {
            id: peer.user_id.clone(),
            tenant_id: peer.tenant_id.clone(),
            email: "peer@example.com".into(),
            display_name: "Peer".into(),
            password_hash: "synthetic-password-sentinel".into(),
            role: memoswish_core::Role::Learner,
            created_at: now,
        })
        .await
        .unwrap();
        let export = repo.account_export(&peer.tenant_id, &peer.user_id, false).await.unwrap();
        assert!(export["feedback_events"].as_array().unwrap().is_empty());
        assert!(!export.to_string().contains("synthetic-password-sentinel"));
        let export = repo.account_export("other-tenant", &p.user_id, false).await.unwrap();
        assert!(export["feedback_events"].as_array().unwrap().is_empty());
        let export = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
        let row = export["feedback_events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["body"]["event_id"].as_str() == Some("future-first"))
            .unwrap();
        let mut batch = examples::sample_feedback_batch();
        batch.session_id = row["session_id"].as_str().unwrap().into();
        batch.events = vec![ImplicitFeedback::deserialize(&row["body"]).unwrap()];
        RestartReceipt {
            batches: vec![batch, clipped_batch],
            memory: repo.get_versioned_memory(&p.tenant_id, &p.user_id, "card-004").await.unwrap().unwrap(),
            provenance: exported_provenance(repo.as_ref(), &p, "card-004").await,
        }
    }
}

#[cfg(test)]
#[path = "s24_tests.rs"]
mod s24_tests;

#[cfg(test)]
mod configuration_validation_tests {
    use super::*;
    #[test]
    fn invalid_numeric_policies_fail_without_a_repository() {
        for weight in [-0.1, f64::NAN, f64::INFINITY] {
            assert!(FeedConfig { new_weight: weight, ..Default::default() }.validate().is_err());
        }
        for cfg in [
            FeedConfig { max_page: 0, ..Default::default() },
            FeedConfig { default_page: 51, ..Default::default() },
            FeedConfig { max_page: 51, ..Default::default() },
            FeedConfig { recent_window: usize::MAX, ..Default::default() },
            FeedConfig { window_before: 255, window_after: 255, ..Default::default() },
            FeedConfig { due_weight: f64::MAX, new_weight: f64::MAX, ..Default::default() },
            FeedConfig { due_weight: 0.0, new_weight: 0.0, reinforce_weight: 0.0, ..Default::default() },
            FeedConfig { fsrs_parameters: vec![f32::NAN; 21], ..Default::default() },
            FeedConfig { desired_retention: f64::NAN, ..Default::default() },
            FeedConfig { signals: SignalPolicy { idle_ms: 100, ..Default::default() }, ..Default::default() },
        ] {
            assert!(cfg.validate().is_err(), "{cfg:?}");
        }
        FeedConfig::default().validate().unwrap();
    }
}
