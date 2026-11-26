//! 同学习者发页的进程内 FIFO；数据库围栏仍负责跨实例正确性。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use memoswish_core::{CoreError, CoreResult};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

// 包含持有者，十请求突发仍有余量；唯一期限只约束排队，不取消已接受的写入。
const MAX_ADMITTED: usize = 32;
const WAIT_DEADLINE: Duration = Duration::from_secs(2);
type Key = (String, String);

struct Entry {
    lock: Arc<AsyncMutex<()>>,
    admitted: usize,
}

pub(crate) struct Coordinator {
    entries: Mutex<HashMap<Key, Entry>>,
    deadline: Duration,
}

impl Default for Coordinator {
    fn default() -> Self {
        Self { entries: Mutex::new(HashMap::new()), deadline: WAIT_DEADLINE }
    }
}

impl Coordinator {
    pub(crate) async fn acquire(self: &Arc<Self>, tenant: &str, user: &str) -> CoreResult<Guard> {
        let key = (tenant.to_owned(), user.to_owned());
        let registration = {
            // 注册与注销使用同一短同步锁，不能在 await 时持有它。
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let entry = entries
                .entry(key.clone())
                .or_insert_with(|| Entry { lock: Arc::new(AsyncMutex::new(())), admitted: 0 });
            if entry.admitted == MAX_ADMITTED {
                return Err(CoreError::Unavailable("feed learner queue is full; retry the same request".into()));
            }
            entry.admitted += 1;
            Registration { coordinator: self.clone(), key, lock: entry.lock.clone() }
        };
        let lock = tokio::time::timeout(self.deadline, registration.lock.clone().lock_owned()).await.map_err(|_| {
            CoreError::Unavailable("feed learner queue deadline exceeded; retry the same request".into())
        })?;
        Ok(Guard { _lock: lock, _registration: registration })
    }

    #[cfg(test)]
    pub(crate) fn registered(&self) -> usize {
        self.entries.lock().unwrap().values().map(|entry| entry.admitted).sum()
    }
}

struct Registration {
    coordinator: Arc<Coordinator>,
    key: Key,
    lock: Arc<AsyncMutex<()>>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut entries = self.coordinator.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get_mut(&self.key).expect("registered learner must exist");
        entry.admitted -= 1;
        // 最后一个持有者或等待者注销后才可移除，防止旧锁仍在使用时同键产生新锁。
        if entry.admitted == 0 {
            entries.remove(&self.key);
        }
    }
}

pub(crate) struct Guard {
    // 字段按声明顺序释放，必须先释放异步锁，再注销键。
    _lock: OwnedMutexGuard<()>,
    _registration: Registration,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    pub(crate) fn pending<F: Future>(future: Pin<&mut F>) {
        assert!(matches!(future.poll(&mut Context::from_waker(Waker::noop())), Poll::Pending));
    }

    #[tokio::test]
    async fn fifo_cancellation_and_no_split_lock() {
        let coordinator = Arc::new(Coordinator::default());
        let holder = coordinator.acquire("t", "u").await.unwrap();
        let mut first = Box::pin(coordinator.acquire("t", "u"));
        let mut cancelled = Box::pin(coordinator.acquire("t", "u"));
        let mut last = Box::pin(coordinator.acquire("t", "u"));
        pending(first.as_mut());
        pending(cancelled.as_mut());
        pending(last.as_mut());
        drop(cancelled);
        assert_eq!(coordinator.registered(), 3);
        // 同 user 的其他 tenant、同 tenant 的其他 user 都能立即前进。
        drop(coordinator.acquire("other", "u").await.unwrap());
        drop(coordinator.acquire("t", "other").await.unwrap());
        drop(holder);
        let mut newcomer = Box::pin(coordinator.acquire("t", "u"));
        pending(newcomer.as_mut());
        pending(last.as_mut());
        let first = first.await.unwrap();
        pending(last.as_mut());
        drop(first);
        pending(newcomer.as_mut());
        drop(last.await.unwrap());
        drop(newcomer.await.unwrap());
        assert_eq!(coordinator.registered(), 0);
        assert!(coordinator.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn overflow_and_deadline_release_registration() {
        let coordinator = Arc::new(Coordinator { deadline: Duration::ZERO, ..Default::default() });
        let holder = coordinator.acquire("t", "u").await.unwrap();
        assert!(matches!(coordinator.acquire("t", "u").await, Err(CoreError::Unavailable(_))));
        assert_eq!(coordinator.registered(), 1);
        drop(holder);
        drop(coordinator.acquire("t", "u").await.unwrap());
        assert!(coordinator.entries.lock().unwrap().is_empty());

        let coordinator = Arc::new(Coordinator::default());
        let holder = coordinator.acquire("t", "u").await.unwrap();
        let mut queued: Vec<_> = (1..MAX_ADMITTED).map(|_| Box::pin(coordinator.acquire("t", "u"))).collect();
        for future in &mut queued {
            pending(future.as_mut());
        }
        assert!(matches!(coordinator.acquire("t", "u").await, Err(CoreError::Unavailable(_))));
        drop(queued);
        drop(holder);
        assert!(coordinator.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn aborting_holder_releases_waiter() {
        let coordinator = Arc::new(Coordinator::default());
        let holder = coordinator.acquire("t", "u").await.unwrap();
        let task = tokio::spawn(async move {
            let _holder = holder;
            std::future::pending::<()>().await;
        });
        let mut waiter = Box::pin(coordinator.acquire("t", "u"));
        pending(waiter.as_mut());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(waiter.await.unwrap());
        assert!(coordinator.entries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancelling_granted_waiter_preserves_next_place() {
        let coordinator = Arc::new(Coordinator::default());
        let holder = coordinator.acquire("t", "u").await.unwrap();
        let mut cancelled = Box::pin(coordinator.acquire("t", "u"));
        let mut next = Box::pin(coordinator.acquire("t", "u"));
        pending(cancelled.as_mut());
        pending(next.as_mut());
        // 已唤醒但尚未被再次轮询的等待者取消，不能吞掉锁或让新来者超车。
        drop(holder);
        drop(cancelled);
        let mut newcomer = Box::pin(coordinator.acquire("t", "u"));
        pending(newcomer.as_mut());
        drop(next.await.unwrap());
        drop(newcomer.await.unwrap());
        assert!(coordinator.entries.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cleanup_never_splits_one_keys_lock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let coordinator = Arc::new(Coordinator::default());
        let active = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let coordinator = coordinator.clone();
            let active = active.clone();
            tasks.spawn(async move {
                for _ in 0..100 {
                    let guard = coordinator.acquire("t", "u").await.unwrap();
                    assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                    tokio::task::yield_now().await;
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    drop(guard);
                    tokio::task::yield_now().await;
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert!(coordinator.entries.lock().unwrap().is_empty());
    }
}
