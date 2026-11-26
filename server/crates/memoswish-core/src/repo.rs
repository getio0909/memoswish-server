//! 持久化抽象。默认实现见 `memoswish-storage`（SQLite），云原生实现（PostgreSQL）在 `commercial-saas` 路线中补齐。
//!
//! 业务方法显式接收 `tenant_id`；认证前全局索引的窄例外见 `oauth::OAuthIndex` 与 ADR 0010。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use memoswish_protocol::{BgmTrack, Card, Deck, FeedPage, FeedQuery, ImplicitFeedback};
use serde::{Deserialize, Serialize};

use crate::error::CoreResult;
use crate::principal::Role;

/// 租户。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: String,
    pub name: String,
    /// 套餐：`self_hosted` | `free` | `pro` | `team`。
    pub plan: String,
    pub created_at: DateTime<Utc>,
}

/// 全局账户与指定工作区成员关系的兼容读取投影；角色只由成员关系保存。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub display_name: String,
    /// Argon2id PHC 字符串；单用户模式的本地所有者为空串。
    pub password_hash: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

/// API Token（只存哈希，明文仅在创建时返回一次）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiTokenRecord {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub name: String,
    pub token_hash: String,
    pub generations: crate::principal::CredentialGenerations,
    /// scope 列表，`*` 表示继承角色全部权限。
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// 用户对单张卡的 FSRS 记忆状态。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryState {
    pub tenant_id: String,
    pub user_id: String,
    pub card_id: String,
    /// 记忆稳定性 S（天）。
    pub stability: f64,
    /// 难度 D（1~10）。
    pub difficulty: f64,
    pub reps: u32,
    pub lapses: u32,
    pub exposures: u32,
    pub last_review: Option<DateTime<Utc>>,
    pub due: Option<DateTime<Utc>>,
    /// 是否在重点记忆库（双击 / 多次循环）。
    pub starred: bool,
    /// 最近一次评分 1~4。
    pub last_rating: Option<u8>,
}

/// 内部投影快照；版本不进入公开记忆模型或线协议。
#[derive(Debug, Clone, PartialEq)]
pub struct VersionedMemory {
    pub state: MemoryState,
    pub version: i64,
}

/// 单条事件原子应用的结果；重试必须重新读取并计算投影。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningEventOutcome {
    Applied,
    Duplicate,
    PayloadConflict,
    Retry,
    MissingScope,
    MissingCard,
    InvalidDelivery,
}

/// 信息流会话（用于 slot 连续编号与近期去重）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedSession {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub next_slot: u64,
    /// 最近下发的卡片 ID（最新在末尾，上限由 feed 引擎控制）。
    pub recent_card_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 接受序列中的调度处置；不改变原始观察身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningDisposition {
    Scheduled,
    LateNotScheduled,
    FutureNotScheduled,
    NotRated,
}

/// 已解析的信号阈值，避免只记录无法恢复配置的版本标签。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalThresholds {
    pub fast_swipe_ms: u32,
    pub reinforce_loops: u32,
    pub slow_flip_ms: u32,
    pub idle_ms: u32,
}

/// 计算后继投影时实际采用的内部应用策略，不是卡片发放策略。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearningApplication {
    pub disposition: LearningDisposition,
    pub effective_at: Option<DateTime<Utc>>,
    pub star: bool,
    pub signal_version: String,
    pub signal_thresholds: SignalThresholds,
    pub scheduler_algorithm: String,
    pub scheduler_package_version: String,
    pub scheduler_adapter_version: String,
    /// v2 保存补全并裁剪后的实际模型参数，v1 保存补全的构造器输入。
    pub scheduler_parameters: Vec<f32>,
    pub desired_retention: f64,
    pub chronology_version: String,
    pub day_policy_version: String,
    pub attribution_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_delivery: Option<DeliveryAttribution>,
}

/// 与事件和后继投影同时提交的接受凭据；旧事件保持未知。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LearningEventProvenance {
    #[serde(flatten)]
    pub application: LearningApplication,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub inferred_rating: Option<u8>,
    pub predecessor_version: Option<i64>,
    pub successor_version: i64,
    pub revision_at_acceptance: u32,
}

/// 已入库的埋点事件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackEventRecord {
    pub tenant_id: String,
    pub user_id: String,
    pub session_id: String,
    pub event: ImplicitFeedback,
    /// 由信号策略推导出的 FSRS 评分；`None` 表示忽略。
    pub rating: Option<u8>,
    pub received_at: DateTime<Utc>,
    /// 历史插入允许未知；生产原子接受必须提供策略。
    #[serde(default)]
    pub application: Option<LearningApplication>,
}

/// 发页命令的稳定请求身份；一次服务调用的全部重试复用本对象。
#[derive(Debug, Clone)]
pub struct FeedIssuanceRequest {
    pub query: FeedQuery,
    pub new_session_id: String,
    pub legacy_request_id: String,
    pub now: DateTime<Utc>,
}

/// 写事务之外计算候选时读取的会话版本。
#[derive(Debug, Clone, PartialEq)]
pub struct FeedIssuanceState {
    pub session: FeedSession,
    pub revision: i64,
    pub replayable: bool,
    pub controls_epoch: i64,
    pub desired_retention: Option<f64>,
}

/// 页回执和后继会话必须在同一事务提交。
#[derive(Debug, Clone)]
pub struct FeedIssuanceCandidate {
    pub expected: FeedIssuanceState,
    pub successor: FeedSession,
    pub page: FeedPage,
    pub policy: Option<DeliveryPolicy>,
}

/// 读取结果和提交结果共用明确的可重试结果。
#[derive(Debug, Clone, PartialEq)]
pub enum FeedIssuanceOutcome {
    Ready(FeedIssuanceState),
    Committed(FeedPage),
    Retry(crate::observability::FeedRetryCause),
}

/// 用户与权限持久化。
#[async_trait]
pub trait AuthRepo: Send + Sync {
    async fn upsert_tenant(&self, tenant: &TenantRecord) -> CoreResult<()>;
    async fn get_tenant(&self, tenant_id: &str) -> CoreResult<Option<TenantRecord>>;
    /// 原子创建全局账户及其初始成员关系，失败不留下半个账户。
    async fn insert_user(&self, user: &UserRecord) -> CoreResult<()>;
    async fn get_user(&self, tenant_id: &str, user_id: &str) -> CoreResult<Option<UserRecord>>;
    async fn find_user_by_email(&self, email: &str) -> CoreResult<Option<UserRecord>>;
    async fn insert_api_token(&self, token: &ApiTokenRecord) -> CoreResult<()>;
    async fn find_api_token(&self, token_hash: &str) -> CoreResult<Option<ApiTokenRecord>>;
    async fn list_api_tokens(&self, tenant_id: &str) -> CoreResult<Vec<ApiTokenRecord>>;
    async fn revoke_api_token(&self, tenant_id: &str, token_id: &str) -> CoreResult<bool>;
    async fn touch_api_token(&self, token_id: &str, at: DateTime<Utc>) -> CoreResult<()>;
    /// 累加用量并返回累加后的总量。`period` 形如 `2026-10`。
    async fn add_usage(&self, tenant_id: &str, metric: &str, period: &str, amount: i64) -> CoreResult<i64>;
    /// 在单条数据库语句中检查上限并累加；超限时返回 None 且不修改用量。
    async fn try_add_usage(
        &self,
        tenant_id: &str,
        metric: &str,
        period: &str,
        amount: i64,
        limit: i64,
    ) -> CoreResult<Option<i64>>;
    async fn get_usage(&self, tenant_id: &str, metric: &str, period: &str) -> CoreResult<i64>;
}

/// 学习资料持久化。
#[async_trait]
pub trait ContentRepo: Send + Sync {
    async fn insert_deck(&self, tenant_id: &str, deck: &Deck) -> CoreResult<()>;
    /// 原子插入新卡组及全部卡片；任意插入失败时整体回滚。
    async fn insert_deck_with_cards(&self, tenant_id: &str, deck: &Deck, cards: &[Card]) -> CoreResult<()>;
    async fn get_deck(&self, tenant_id: &str, deck_id: &str) -> CoreResult<Option<Deck>>;
    async fn list_decks(&self, tenant_id: &str) -> CoreResult<Vec<Deck>>;
    async fn delete_deck(&self, tenant_id: &str, deck_id: &str) -> CoreResult<bool>;
    /// 仅插入，供导入及初始数据使用；已存在的 ID 不得覆盖。
    async fn insert_card(&self, tenant_id: &str, card: &Card) -> CoreResult<()>;
    /// 在同一事务当前快照上合并全部变更，任意失败整体回滚，返回顺序与请求一致。
    async fn mutate_cards(&self, tenant_id: &str, changes: &[crate::content::CardMutation]) -> CoreResult<Vec<Card>>;
    async fn get_card(&self, tenant_id: &str, card_id: &str) -> CoreResult<Option<Card>>;
    async fn list_cards(
        &self,
        tenant_id: &str,
        deck_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> CoreResult<Vec<Card>>;
    async fn delete_card(&self, tenant_id: &str, card_id: &str) -> CoreResult<bool> {
        self.delete_card_if_revision(tenant_id, card_id, None).await
    }
    async fn delete_card_if_revision(
        &self,
        tenant_id: &str,
        card_id: &str,
        expected_revision: Option<u32>,
    ) -> CoreResult<bool>;
}

/// BGM 曲库持久化。`tenant_id = None` 表示全局共享曲库。
#[async_trait]
pub trait MediaRepo: Send + Sync {
    /// 显式版本仅更新本作用域已有曲目，缺省允许创建或兼容覆盖。
    async fn save_bgm(
        &self,
        tenant_id: Option<&str>,
        track: &BgmTrack,
        expected_revision: Option<u32>,
    ) -> CoreResult<BgmTrack>;
    async fn get_bgm(&self, tenant_id: &str, track_id: &str) -> CoreResult<Option<BgmTrack>>;
    /// 返回租户私有曲目 + 共享曲目。
    async fn list_bgm(&self, tenant_id: &str) -> CoreResult<Vec<BgmTrack>>;
}

/// 记忆模型、埋点与信息流会话持久化。
#[async_trait]
pub trait ReviewRepo: Send + Sync {
    /// 生产反馈在同一事务内核验原始会话凭据与捕获世代，包含归档事件判重路径。
    async fn try_apply_learning_event_for_principal(
        &self,
        principal: &crate::Principal,
        record: &FeedbackEventRecord,
        expected_version: Option<i64>,
        successor: &MemoryState,
    ) -> CoreResult<LearningEventOutcome>;
    /// 可信内部写入核对调用者捕获的账户和成员世代。
    async fn try_apply_learning_event_authorized(
        &self,
        record: &FeedbackEventRecord,
        expected_version: Option<i64>,
        successor: &MemoryState,
        generations: crate::CredentialGenerations,
    ) -> CoreResult<LearningEventOutcome>;
    async fn upsert_memory_authorized(
        &self,
        state: &MemoryState,
        generations: crate::CredentialGenerations,
    ) -> CoreResult<()>;
    async fn insert_feedback_authorized(
        &self,
        record: &FeedbackEventRecord,
        generations: crate::CredentialGenerations,
    ) -> CoreResult<bool>;
    async fn save_session_authorized(
        &self,
        session: &FeedSession,
        generations: crate::CredentialGenerations,
    ) -> CoreResult<()>;

    // 无世代写入仅供可信迁移、测试夹具与兼容内部调用，生产反馈使用主体入口。
    async fn get_versioned_memory(
        &self,
        tenant_id: &str,
        user_id: &str,
        card_id: &str,
    ) -> CoreResult<Option<VersionedMemory>>;
    /// 事件唯一身份、不可变载荷与期望版本的后继投影在一个事务提交。
    async fn try_apply_learning_event(
        &self,
        record: &FeedbackEventRecord,
        expected_version: Option<i64>,
        successor: &MemoryState,
    ) -> CoreResult<LearningEventOutcome>;
    async fn get_memory(&self, tenant_id: &str, user_id: &str, card_id: &str) -> CoreResult<Option<MemoryState>>;
    async fn upsert_memory(&self, state: &MemoryState) -> CoreResult<()>;
    /// 只列出仍有同租户活卡的记忆，不限制数量；历史点读和范围导出保留已删除卡片的记忆。
    async fn list_memory(&self, tenant_id: &str, user_id: &str) -> CoreResult<Vec<MemoryState>>;
    /// 插入埋点事件；`event_id` 重复时返回 `false`。
    async fn insert_feedback(&self, record: &FeedbackEventRecord) -> CoreResult<bool>;
    async fn get_session(&self, tenant_id: &str, user_id: &str, session_id: &str) -> CoreResult<Option<FeedSession>>;
    /// 兼容夹具写入；不得覆盖由发页命令接管的会话。
    async fn save_session(&self, session: &FeedSession) -> CoreResult<()>;
    /// 无候选时恢复回执或读取版本；有候选时重新验证并条件提交。
    async fn feed_issuance(
        &self,
        principal: &crate::Principal,
        request: &FeedIssuanceRequest,
        candidate: Option<&FeedIssuanceCandidate>,
    ) -> CoreResult<FeedIssuanceOutcome>;
    /// 授权后优先恢复已提交身份，不依赖卡片或历史策略仍可重建。
    async fn recover_learning_event(
        &self,
        principal: &crate::Principal,
        record: &FeedbackEventRecord,
    ) -> CoreResult<Option<LearningEventOutcome>>;
    /// 按原始学习作用域读取紧凑投递证据；事务内再次核对。
    async fn get_delivery(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: &str,
        slot: u64,
    ) -> CoreResult<Option<DeliveryRecord>>;
    /// 预览不写学习状态，但必须核验捕获的凭据及世代。
    async fn authorize_feed_preview(&self, p: &crate::Principal) -> CoreResult<()>;
    /// 维护窄入口，仅清理有界过期快照并保留首次身份墓碑。
    async fn expire_feed_sessions(&self, limit: u32) -> CoreResult<u64>;
}

/// 完整活卡域的轻量元数据，不包含卡片正文或资产。
#[derive(Debug, Clone)]
pub struct FeedCardMetadata {
    pub suspended: bool,
    pub buried_until_ms: Option<i64>,
    pub last_issued_seq: i64,
    pub card_id: String,
    pub created_at: DateTime<Utc>,
    pub memory: Option<MemoryState>,
}

/// 候选读取保持在发页写事务之外，最终提交仍核验原主体和正文版本。
#[async_trait]
pub trait FeedCandidateRepo: Send + Sync {
    /// 按创建时间及 ID 流式访问完整作用域的同一读取快照，回调失败必须向调用者传播。
    async fn visit_feed_metadata(
        &self,
        tenant_id: &str,
        user_id: &str,
        deck_id: Option<&str>,
        visit: &mut (dyn FnMut(FeedCardMetadata) -> CoreResult<()> + Send),
    ) -> CoreResult<()>;
    /// 单次批量补全正文，缺失或已移出卡组的目标交由原发页预算重新计算。
    async fn hydrate_feed_cards(
        &self,
        tenant_id: &str,
        deck_id: Option<&str>,
        card_ids: &[String],
    ) -> CoreResult<Vec<Card>>;
    /// 完整活卡域的独立 SQL 聚合，不得与另一次读取拼接成一致快照统计。
    async fn feed_summary(
        &self,
        tenant_id: &str,
        user_id: &str,
        deck_id: Option<&str>,
    ) -> CoreResult<memoswish_protocol::LearningStats>;
    /// 既有响应为未分页数组，完整返回并按最近复习时间倒序排列。
    async fn starred_feed_cards(&self, tenant_id: &str, user_id: &str, deck_id: Option<&str>) -> CoreResult<Vec<Card>>;
}

/// 全局账户索引仅用于账户认证，不授予工作区权限。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MembershipRecord {
    pub tenant_id: String,
    pub role: Role,
    pub generation: i64,
}

/// 账户与成员授权的事务入口，认证前账户索引为窄例外。
#[async_trait]
pub trait MembershipRepo: Send + Sync {
    /// 对外签发在事务内重查当前角色及捕获世代。
    async fn issue_api_token(&self, token: &ApiTokenRecord) -> CoreResult<()>;
    async fn account_by_email(&self, email: &str) -> CoreResult<Option<AccountRecord>>;
    async fn account_by_id(&self, user_id: &str) -> CoreResult<Option<AccountRecord>>;
    async fn account_generation(&self, user_id: &str) -> CoreResult<i64>;
    async fn memberships(&self, user_id: &str) -> CoreResult<Vec<MembershipRecord>>;
    async fn membership_authorize(
        &self,
        tenant_id: &str,
        user_id: &str,
        generations: crate::principal::CredentialGenerations,
    ) -> CoreResult<Role>;
    /// 内部基础原语；组织产品的最后 owner 与离开策略由 S5 实施。
    async fn membership_remove(&self, tenant_id: &str, user_id: &str) -> CoreResult<bool>;
    async fn membership_join(&self, tenant_id: &str, user_id: &str, role: Role) -> CoreResult<i64>;
    async fn account_export_empty(
        &self,
        user_id: &str,
        generation: i64,
    ) -> CoreResult<memoswish_protocol::AccountExport>;
    async fn account_close_empty(&self, user_id: &str, generation: i64) -> CoreResult<crate::identity::ErasureJob>;
}

/// 聚合仓储：服务层统一持有 `Arc<dyn Repository>`。
pub trait Repository:
    crate::learning_controls::LearningControlsRepo
    + crate::password_lifecycle::PasswordLifecycleRepo
    + crate::diagnostics::DiagnosticRepo
    + crate::content_lifecycle_repo::ContentLifecycleRepo
    + crate::maintenance::MaintenanceRepo
    + crate::observability::OperationalRepo
    + crate::library::LibraryRepo
    + crate::privacy::PrivacyRepo
    + crate::erasure::ErasureRepo
    + crate::session::SessionRepo
    + crate::imports::ImportRepo
    + crate::explanations::ExplanationRepo
    + MembershipRepo
    + crate::lifecycle::LifecycleRepo
    + crate::assets::AssetRepo
    + AuthRepo
    + ContentRepo
    + MediaRepo
    + ReviewRepo
    + FeedCandidateRepo
    + crate::oauth::OAuthRepo
    + crate::identity::IdentityRepo
{
}

impl<
    T: crate::learning_controls::LearningControlsRepo
        + crate::password_lifecycle::PasswordLifecycleRepo
        + crate::diagnostics::DiagnosticRepo
        + crate::content_lifecycle_repo::ContentLifecycleRepo
        + crate::maintenance::MaintenanceRepo
        + crate::observability::OperationalRepo
        + crate::library::LibraryRepo
        + crate::privacy::PrivacyRepo
        + crate::erasure::ErasureRepo
        + crate::session::SessionRepo
        + crate::imports::ImportRepo
        + crate::explanations::ExplanationRepo
        + MembershipRepo
        + crate::lifecycle::LifecycleRepo
        + crate::assets::AssetRepo
        + AuthRepo
        + ContentRepo
        + MediaRepo
        + ReviewRepo
        + FeedCandidateRepo
        + crate::oauth::OAuthRepo
        + crate::identity::IdentityRepo,
> Repository for T
{
}

/// 可注入的 UTC 时钟；基础设施在组装点提供实际时钟。
pub trait UtcClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
impl<F: Fn() -> DateTime<Utc> + Send + Sync> UtcClock for F {
    fn now(&self) -> DateTime<Utc> {
        self()
    }
}

/// 发放时的有效配置及算法版本；不包含凭据或资产 URL。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryPolicy {
    pub version: String,
    pub configuration: String,
}
impl DeliveryPolicy {
    pub fn new<T: Serialize>(format_version: &str, configuration: &T) -> CoreResult<Self> {
        use sha2::{Digest, Sha256};
        let configuration = serde_json::to_string(configuration).map_err(crate::CoreError::internal)?;
        let version = format!("{format_version}:{}", hex::encode(Sha256::digest(configuration.as_bytes())));
        Ok(Self { version, configuration })
    }
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> CoreResult<T> {
        serde_json::from_str(&self.configuration).map_err(crate::CoreError::internal)
    }
}

/// 发放修订与接受修订分开保存；历史事件缺少此字段。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryAttribution {
    pub delivery_id: String,
    pub policy_version: String,
    pub revision_at_issuance: u32,
    pub issued_at: DateTime<Utc>,
}

/// 紧凑证据独立于过期的页面快照，随学习者作用域擦除。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub attribution: DeliveryAttribution,
    pub card_id: String,
    pub policy: DeliveryPolicy,
}
