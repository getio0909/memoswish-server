//! 仅接受有限枚举的运维观察端口；不接受身份、错误正文或内容标签。

use async_trait::async_trait;
use std::sync::Arc;

macro_rules! labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn label(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}
labels!(Operation {
    TtsHttp => "tts_http", TtsCommand => "tts_command", ExplanationHttp => "explanation_http",
    DbRead => "db_read", DbWrite => "db_write", DbClaim => "db_claim", DbCleanup => "db_cleanup",
    DbSample => "db_sample", ObjectDelete => "object_delete", Erasure => "erasure", Orphan => "orphan", Retention => "retention"
});
labels!(Outcome {
    Returned => "returned", Timeout => "timeout", TransportError => "transport_error",
    HttpError => "http_error", InvalidResponse => "invalid_response", CommandFailure => "command_failure", Cancelled => "cancelled",
    Error => "error", PoolTimeout => "pool_timeout", Busy => "busy", Closed => "closed"
});
labels!(AdmissionClass {
    Work => "work", Auth => "auth", Oauth => "oauth", Oidc => "oidc",
    PasswordSource => "password_source", PasswordAccount => "password_account", Password => "password", PasswordQueue => "password_admitted", Put => "put",
    Explanation => "explanation", Import => "import"
});
labels!(AdmissionOutcome {
    Accepted => "accepted", Rejected => "rejected", Unavailable => "unavailable",
    FailOpen => "fail_open", Invalid => "invalid", Cancelled => "cancelled"
});
labels!(TaskState { Queued => "queued", Running => "running", Succeeded => "succeeded", Dead => "dead" });
labels!(FeedRetryCause {
    StateMismatch => "state_mismatch", SessionRevision => "session_revision",
    DatabaseBusyLocked => "database_busy_locked", Other => "other"
});
labels!(ReviewOutcome { Accepted => "accepted", Duplicate => "duplicate", Rejected => "rejected" });
labels!(WorkKind {
    Speech => "speech", Bgm => "bgm", Asset => "asset", Import => "import", Erasure => "erasure",
    ManagedWrite => "managed_write", Orphan => "orphan", ExpiredOauth => "expired_oauth", ExpiredOidc => "expired_oidc", Other => "other",
    Explanation => "explanation", Diagnostic => "diagnostic", ExpiredPassword => "expired_password", Lifecycle => "lifecycle", Maintenance => "maintenance"
});

/// 完成只能记录一次；未完成的真实任务在释放 guard 时记录取消。
pub trait ObservationGuard: Send {
    fn finish(&mut self, outcome: Outcome);
}
pub trait Observer: Send + Sync {
    fn start(&self, _operation: Operation) -> Box<dyn ObservationGuard> {
        Box::new(Noop)
    }
    fn maintenance(&self, _kind: crate::maintenance::TaskKind, _success: bool) {}
    fn feed_retry(&self, _cause: FeedRetryCause) {}
    fn review(&self, _outcome: ReviewOutcome) {}
    fn disposition(&self, _disposition: crate::repo::LearningDisposition) {}
    fn admission(&self, _class: AdmissionClass, _outcome: AdmissionOutcome) {}
    fn slot(&self, _class: AdmissionClass, _delta: i64) {}
    fn capacity(&self, _class: AdmissionClass, _used: usize, _capacity: usize) {}
}
#[derive(Default)]
pub struct Noop;
impl Observer for Noop {}
impl ObservationGuard for Noop {
    fn finish(&mut self, _: Outcome) {}
}
pub fn noop() -> Arc<dyn Observer> {
    Arc::new(Noop)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PoolSnapshot {
    pub size: u32,
    pub idle: usize,
    pub capacity: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct PendingWork {
    pub kind: WorkKind,
    pub count: i64,
    pub unknown: i64,
    pub future: i64,
    pub oldest_ms: Option<i64>,
}
#[derive(Clone, Debug)]
pub struct MaintenanceCount {
    pub kind: crate::maintenance::TaskKind,
    pub state: TaskState,
    pub count: i64,
}
#[derive(Clone, Debug)]
pub struct OperationalSnapshot {
    pub observed_at_ms: i64,
    pub pending: Vec<PendingWork>,
    pub maintenance: Vec<MaintenanceCount>,
}

/// 仅守护进程的宿主级观察使用全局聚合；不可转为租户 REST/MCP 查询。
#[async_trait]
pub trait OperationalRepo: Send + Sync {
    fn pool_snapshot(&self) -> PoolSnapshot;
    async fn operational_snapshot(&self) -> crate::CoreResult<OperationalSnapshot>;
}

/// slot 随真实任务所有权移动；调用者取消不提前释放后台拥有的 slot。
pub struct Slot {
    observer: Arc<dyn Observer>,
    class: AdmissionClass,
}
impl Slot {
    pub fn new(observer: Arc<dyn Observer>, class: AdmissionClass) -> Self {
        observer.slot(class, 1);
        Self { observer, class }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.observer.slot(self.class, -1);
    }
}
pub struct AdmissionAttempt {
    observer: Arc<dyn Observer>,
    class: AdmissionClass,
    complete: bool,
}
impl AdmissionAttempt {
    pub fn new(observer: Arc<dyn Observer>, class: AdmissionClass) -> Self {
        Self { observer, class, complete: false }
    }
    pub fn finish(&mut self, outcome: AdmissionOutcome) {
        if !self.complete {
            self.observer.admission(self.class, outcome);
            self.complete = true;
        }
    }
}
impl Drop for AdmissionAttempt {
    fn drop(&mut self) {
        self.finish(AdmissionOutcome::Cancelled);
    }
}
