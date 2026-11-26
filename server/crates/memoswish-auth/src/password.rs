//! Argon2id 密码哈希。

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use memoswish_core::{CoreError, CoreResult};

/// 最短密码长度。
pub const MIN_PASSWORD_LEN: usize = 8;

/// 生成 PHC 格式哈希。
pub fn hash_password(password: &str) -> CoreResult<String> {
    if password.len() > 1024 {
        return Err(CoreError::invalid("password exceeds 1024 bytes"));
    }
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(CoreError::invalid(format!("password must be at least {MIN_PASSWORD_LEN} characters")));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CoreError::internal(format!("password hashing failed: {e}")))
}

/// 校验密码；哈希为空或格式错误时返回 `false`。
pub fn verify_password(password: &str, phc: &str) -> bool {
    if password.len() > 1024 || !accepted_phc(phc) {
        return false;
    }
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong horse", &h));
        assert!(!verify_password("x", ""));
        assert!(hash_password("short").is_err());
    }
}

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// 固定合法 PHC 仅用于失败路径的同成本计算，不是任何账户的密码。
const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 所有密码入口共用执行预算，内存上限为 workers × 19456 KiB。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordConfig {
    pub workers: usize,
    pub queue: usize,
    pub max_bytes: usize,
}
impl Default for PasswordConfig {
    fn default() -> Self {
        Self { workers: 2, queue: 8, max_bytes: 1024 }
    }
}
impl PasswordConfig {
    pub fn validate(&self) -> CoreResult<()> {
        if !(1..=16).contains(&self.workers) || self.queue > 64 || !(32..=1024).contains(&self.max_bytes) {
            return Err(CoreError::invalid("invalid password work budget"));
        }
        Ok(())
    }
}

// 中间件的来源许可证随实际计算存活，取消 HTTP future 不退还正在使用的来源容量。
tokio::task_local! {
    static SOURCE_PERMIT: Arc<OwnedSemaphorePermit>;
}
pub async fn with_source_permit<F: std::future::Future>(permit: OwnedSemaphorePermit, future: F) -> F::Output {
    SOURCE_PERMIT.scope(Arc::new(permit), future).await
}

/// 克隆只共享预算，不创建新的计算池。
#[derive(Clone)]
pub struct PasswordRunner {
    config: PasswordConfig,
    observer: Arc<dyn memoswish_core::observability::Observer>,
    running: Arc<Semaphore>,
    admitted: Arc<Semaphore>,
    closed: Arc<std::sync::Mutex<bool>>,
}
impl PasswordRunner {
    pub fn new(config: PasswordConfig) -> CoreResult<Self> {
        config.validate()?;
        Ok(Self {
            observer: memoswish_core::observability::noop(),
            running: Arc::new(Semaphore::new(config.workers)),
            admitted: Arc::new(Semaphore::new(config.workers + config.queue)),
            closed: Arc::new(std::sync::Mutex::new(false)),
            config,
        })
    }
    pub fn with_observer(mut self, observer: Arc<dyn memoswish_core::observability::Observer>) -> Self {
        use memoswish_core::observability::AdmissionClass;
        observer.capacity(AdmissionClass::Password, 0, self.config.workers);
        observer.capacity(AdmissionClass::PasswordQueue, 0, self.config.workers + self.config.queue);
        self.observer = observer;
        self
    }

    /// 关闭与登记共用锁；已接收的计算及排队者继续持有原许可证。
    pub fn close(&self) {
        *self.closed.lock().unwrap() = true;
    }
    /// 等待真实计算归还全部容量；取消等待不会取消 blocking 计算或提前退还许可证。
    pub async fn wait(&self) {
        self.close();
        let _drained = self
            .admitted
            .acquire_many((self.config.workers + self.config.queue) as u32)
            .await
            .expect("password admission semaphore is never closed");
    }
    pub fn validate_input(&self, password: &str) -> CoreResult<()> {
        if password.len() > self.config.max_bytes {
            return Err(CoreError::invalid("password input too large"));
        }
        Ok(())
    }
    async fn run<T: Send + 'static>(&self, work: impl FnOnce() -> T + Send + 'static) -> CoreResult<T> {
        use memoswish_core::observability::{AdmissionAttempt, AdmissionClass, AdmissionOutcome, Slot};
        let mut attempt = AdmissionAttempt::new(self.observer.clone(), AdmissionClass::Password);
        let admitted = {
            let closed = self.closed.lock().unwrap();
            if *closed {
                attempt.finish(AdmissionOutcome::Unavailable);
                return Err(CoreError::Unavailable("password work admission is closed".into()));
            }
            self.admitted.clone().try_acquire_owned().map_err(|_| {
                attempt.finish(AdmissionOutcome::Rejected);
                CoreError::QuotaExceeded("password work capacity reached".into())
            })?
        };
        let admitted_slot = Slot::new(self.observer.clone(), AdmissionClass::PasswordQueue);
        let running = self
            .running
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| CoreError::Unavailable("password runner unavailable".into()))?;
        let running_slot = Slot::new(self.observer.clone(), AdmissionClass::Password);
        attempt.finish(AdmissionOutcome::Accepted);
        let source = SOURCE_PERMIT.try_with(Arc::clone).ok();
        tokio::task::spawn_blocking(move || {
            let _ownership = (admitted, running, source, admitted_slot, running_slot);
            work()
        })
        .await
        .map_err(|_| CoreError::Unavailable("password worker failed".into()))
    }
    pub async fn hash(&self, password: &str) -> CoreResult<String> {
        self.validate_input(password)?;
        let password = password.to_owned();
        self.run(move || hash_password(&password)).await?
    }
    pub async fn verify(&self, password: &str, phc: Option<&str>) -> CoreResult<bool> {
        self.validate_input(password)?;
        let accepted = phc.is_some_and(accepted_phc);
        let phc = phc.filter(|_| accepted).unwrap_or(DUMMY).to_owned();
        let password = password.to_owned();
        self.run(move || {
            let valid = verify_password(&password, &phc);
            accepted && valid
        })
        .await
    }
}

// 只接受本服务既有默认参数，避免存储损坏放大成本或跳过失败计算。
fn accepted_phc(phc: &str) -> bool {
    if phc.len() > 256 {
        return false;
    }
    let Ok(hash) = PasswordHash::new(phc) else {
        return false;
    };
    hash.algorithm.as_str() == "argon2id"
        && hash.version == Some(19)
        && hash.params.to_string() == "m=19456,t=2,p=1"
        && hash.salt.is_some_and(|salt| {
            let mut decoded = [0; 16];
            salt.decode_b64(&mut decoded).is_ok_and(|bytes| bytes.len() == 16)
        })
        && hash.hash.is_some_and(|h| h.len() == 32)
}

#[cfg(test)]
mod runner_tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_drains_cancelled_computation_and_queue_without_reopening_on_timeout() {
        let runner = PasswordRunner::new(PasswordConfig { workers: 1, queue: 1, max_bytes: 1024 }).unwrap();
        let (started, observed) = tokio::sync::oneshot::channel();
        let (release, paused) = std::sync::mpsc::channel();
        let request = {
            let runner = runner.clone();
            tokio::spawn(async move {
                runner
                    .run(move || {
                        started.send(()).unwrap();
                        paused.recv().unwrap()
                    })
                    .await
            })
        };
        observed.await.unwrap();
        let queued = {
            let runner = runner.clone();
            tokio::spawn(async move { runner.run(|| 42).await })
        };
        while runner.admitted.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        runner.close();
        assert_eq!(runner.run(|| ()).await.unwrap_err().http_status(), 503);
        // 宿主预算耗尽只能结束等待，不能把仍在计算的容量当成已归还。
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10), runner.wait()).await.is_err());
        assert_eq!(runner.admitted.available_permits(), 0);
        assert!(!queued.is_finished());
        assert_eq!(runner.run(|| ()).await.unwrap_err().http_status(), 503);
        release.send(()).unwrap();
        runner.wait().await;
        assert_eq!(queued.await.unwrap().unwrap(), 42);
        assert_eq!(runner.admitted.available_permits(), 2);
        assert_eq!(runner.running.available_permits(), 1);
        assert_eq!(runner.hash("password123").await.unwrap_err().http_status(), 503);
        runner.close();
        runner.wait().await;
    }

    #[tokio::test]
    async fn bounded_work_survives_cancellation_and_waiters_release_capacity() {
        use memoswish_core::observability::{AdmissionClass, AdmissionOutcome, Observer};
        #[derive(Default)]
        struct Slots {
            running: std::sync::atomic::AtomicI64,
            admitted: std::sync::atomic::AtomicI64,
            rejected: std::sync::atomic::AtomicI64,
        }
        impl Observer for Slots {
            fn slot(&self, class: AdmissionClass, delta: i64) {
                match class {
                    AdmissionClass::Password => {
                        self.running.fetch_add(delta, std::sync::atomic::Ordering::SeqCst);
                    }
                    AdmissionClass::PasswordQueue => {
                        self.admitted.fetch_add(delta, std::sync::atomic::Ordering::SeqCst);
                    }
                    _ => {}
                }
            }
            fn admission(&self, _: AdmissionClass, outcome: AdmissionOutcome) {
                if outcome == AdmissionOutcome::Rejected {
                    self.rejected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        let slots = Arc::new(Slots::default());
        let runner = PasswordRunner::new(PasswordConfig { workers: 1, queue: 1, max_bytes: 1024 })
            .unwrap()
            .with_observer(slots.clone());
        let source = Arc::new(Semaphore::new(1));
        let permit = source.clone().try_acquire_owned().unwrap();
        let (started, observed) = tokio::sync::oneshot::channel();
        let (release, paused) = std::sync::mpsc::channel();
        let request = {
            let runner = runner.clone();
            tokio::spawn(with_source_permit(permit, async move {
                runner
                    .run(move || {
                        started.send(()).unwrap();
                        paused.recv().unwrap();
                    })
                    .await
            }))
        };
        observed.await.unwrap();
        let waiter = {
            let runner = runner.clone();
            tokio::spawn(async move { runner.run(|| ()).await })
        };
        while runner.admitted.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(runner.run(|| ()).await.unwrap_err().http_status(), 429);
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(runner.running.available_permits(), 0);
        assert_eq!(slots.running.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(slots.admitted.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(slots.rejected.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(runner.admitted.available_permits(), 0);
        assert!(source.clone().try_acquire_owned().is_err());
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(runner.admitted.available_permits(), 1);
        assert_eq!(slots.admitted.load(std::sync::atomic::Ordering::SeqCst), 1);
        release.send(()).unwrap();
        runner.run(|| ()).await.unwrap();
        assert_eq!(runner.running.available_permits(), 1);
        assert_eq!(runner.admitted.available_permits(), 2);
        assert!(source.try_acquire_owned().is_ok());
        assert_eq!(slots.running.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(slots.admitted.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn input_cost_bounds_and_equivalent_failure_work() {
        for config in [
            PasswordConfig { workers: 0, ..Default::default() },
            PasswordConfig { workers: 17, ..Default::default() },
            PasswordConfig { queue: 65, ..Default::default() },
            PasswordConfig { max_bytes: 31, ..Default::default() },
            PasswordConfig { max_bytes: 1025, ..Default::default() },
        ] {
            assert!(PasswordRunner::new(config).is_err());
        }
        assert!(accepted_phc(DUMMY));
        // PHC 字段解析不等于盐可解码，非规范尾位必须回退到完整 dummy 计算。
        let malformed_salt = DUMMY.replace("$AAAAAAAAAAAAAAAAAAAAAA$", "$AAAAAAAAAAAAAAAAAAAAAB$");
        assert!(PasswordHash::new(&malformed_salt).is_ok());
        assert!(!accepted_phc(&malformed_salt));
        let runner = PasswordRunner::new(PasswordConfig::default()).unwrap();
        let hash = runner.hash("correct horse").await.unwrap();
        assert!(accepted_phc(&hash));
        assert!(runner.verify("correct horse", Some(&hash)).await.unwrap());
        for stored in [
            None,
            Some(""),
            Some("broken"),
            Some(&malformed_salt),
            Some(&hash),
            Some(&DUMMY.replace("m=19456", "m=999999999")),
            Some(&DUMMY.replace("t=2", "t=999999")),
            Some(&DUMMY.replace("p=1", "p=32")),
            Some(&DUMMY.replace("argon2id", "argon2i")),
            Some(&"x".repeat(257)),
        ] {
            assert!(!runner.verify("wrong horse", stored).await.unwrap());
        }
        let largest = "x".repeat(1024);
        assert!(runner.hash(&largest).await.is_ok());
        assert!(!runner.verify(&largest, None).await.unwrap());
        assert!(runner.hash(&(largest.clone() + "x")).await.is_err());
        assert!(runner.verify(&(largest + "x"), None).await.is_err());
        assert!(runner.hash("short").await.is_err());
    }
}
