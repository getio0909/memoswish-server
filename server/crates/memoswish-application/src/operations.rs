//! 应用层拥有已接收的后台任务，关闭传输不能取消提交或补偿。

use std::sync::{Arc, Mutex};

use memoswish_core::{CoreError, CoreResult};
use tokio::task::JoinHandle;
use tokio_util::task::TaskTracker;

#[derive(Default)]
struct State {
    closed: Mutex<bool>,
    tasks: TaskTracker,
}

/// 所有传输共享的进程内任务归属；持久恢复仍由后续导入生命周期负责。
#[derive(Clone, Default)]
pub struct OperationTracker(Arc<State>);

impl OperationTracker {
    pub fn spawn<F>(&self, operation: F) -> CoreResult<JoinHandle<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // 关闭与登记共用锁，禁止排空观察到空集合后又接收新任务。
        let closed = self.0.closed.lock().unwrap();
        if *closed {
            return Err(CoreError::Unavailable("application operation admission is closed; retry later".into()));
        }
        let control = OperationControl::current();
        Ok(self.0.tasks.spawn(async move { control.scope(operation).await }))
    }

    pub fn close(&self) {
        let mut closed = self.0.closed.lock().unwrap();
        *closed = true;
        self.0.tasks.close();
    }

    pub async fn wait(&self) {
        self.0.tasks.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_tracker_rejects_new_work_and_retains_detached_work() {
        let operations = OperationTracker::default();
        let (release, blocked) = tokio::sync::oneshot::channel::<()>();
        let (finished, completed) = tokio::sync::oneshot::channel();
        let task = operations
            .spawn(async move {
                blocked.await.unwrap();
                finished.send(()).unwrap();
            })
            .unwrap();
        drop(task);
        operations.close();
        assert!(operations.spawn(async { panic!("closed admission must not execute") }).is_err());
        let drain = operations.wait();
        tokio::pin!(drain);
        tokio::select! {
            biased;
            _ = &mut drain => panic!("accepted operation still owns pending work"),
            _ = tokio::task::yield_now() => {},
        }
        release.send(()).unwrap();
        drain.await;
        completed.await.unwrap();
    }
}

// 控制只作用于当前应用调用，后台任务继承控制但不继承传输 peer。
tokio::task_local! {
    static CONTROL: OperationControl;
}

/// 取消请求不撤销已进入接收事务的责任，事务必须由原拥有者解析。
#[derive(Clone)]
pub struct OperationControl {
    cancellation: tokio_util::sync::CancellationToken,
    phase: tokio::sync::watch::Sender<&'static str>,
}

impl Default for OperationControl {
    fn default() -> Self {
        Self::new(tokio_util::sync::CancellationToken::new())
    }
}

impl OperationControl {
    pub fn new(cancellation: tokio_util::sync::CancellationToken) -> Self {
        Self { cancellation, phase: tokio::sync::watch::channel("preparing").0 }
    }

    pub fn current() -> Self {
        CONTROL.try_with(Clone::clone).unwrap_or_default()
    }

    pub async fn scope<F: Future>(&self, operation: F) -> F::Output {
        CONTROL.scope(self.clone(), operation).await
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<&'static str> {
        self.phase.subscribe()
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub fn checkpoint(&self) -> CoreResult<()> {
        if self.cancellation.is_cancelled() {
            return Err(CoreError::Unavailable(
                "operation cancelled before acceptance; no new responsibility accepted".into(),
            ));
        }
        Ok(())
    }

    pub fn begin_acceptance(&self) -> CoreResult<()> {
        self.checkpoint()?;
        self.phase.send_replace("accepting");
        Ok(())
    }

    pub fn accepted(&self) {
        self.phase.send_replace("accepted");
    }
}

#[cfg(test)]
mod control_tests {
    use super::*;

    #[tokio::test]
    async fn acceptance_wins_cancellation_and_lost_waiter_retains_owner() {
        let operations = OperationTracker::default();
        let control = OperationControl::default();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let (finished, result) = tokio::sync::oneshot::channel();
        let (task,) = control
            .scope(async {
                (operations
                    .spawn(async move {
                        let inherited = OperationControl::current();
                        inherited.begin_acceptance().unwrap();
                        entered.send(()).unwrap();
                        blocked.await.unwrap();
                        inherited.accepted();
                        finished.send("accepted").unwrap();
                    })
                    .unwrap(),)
            })
            .await;
        ready.await.unwrap();
        control.cancel();
        drop(task);
        operations.close();
        release.send(()).unwrap();
        operations.wait().await;
        assert_eq!(result.await.unwrap(), "accepted");
        assert_eq!(*control.subscribe().borrow(), "accepted");
    }

    #[tokio::test]
    async fn cancellation_before_acceptance_prohibits_entering_transaction() {
        let control = OperationControl::default();
        control.cancel();
        assert!(control.begin_acceptance().is_err());
        assert_eq!(*control.subscribe().borrow(), "preparing");
    }
}
