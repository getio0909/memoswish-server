//! 一个安装共享状态与首次关闭期限；重复信号和宿主取消不能重置预算。
use std::{sync::Mutex, time::Duration};
use tokio::{sync::watch, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Starting,
    Running,
    Draining,
    Stopped,
    Failed,
}

pub(crate) struct Lifecycle {
    phase: watch::Sender<Phase>,
    deadline: Mutex<Option<Instant>>,
    budget: Duration,
}

impl Lifecycle {
    pub(crate) fn new(seconds: u64) -> Self {
        Self {
            phase: watch::channel(Phase::Starting).0,
            deadline: Mutex::new(None),
            budget: Duration::from_secs(seconds),
        }
    }
    pub(crate) fn phase(&self) -> Phase {
        *self.phase.borrow()
    }
    pub(crate) fn set(&self, phase: Phase) {
        self.phase.send_replace(phase);
    }
    pub(crate) async fn draining(&self) {
        let mut receiver = self.phase.subscribe();
        let _ = receiver.wait_for(|phase| matches!(phase, Phase::Draining | Phase::Stopped | Phase::Failed)).await;
    }
    pub(crate) fn drain(&self) -> Instant {
        let mut deadline = self.deadline.lock().unwrap();
        let deadline = *deadline.get_or_insert_with(|| Instant::now() + self.budget);
        if !matches!(self.phase(), Phase::Stopped | Phase::Failed) {
            self.set(Phase::Draining);
        }
        deadline
    }
}

/// 保留每个真实连接的任务句柄；期限后取消并等待，避免宿主运行时遗留 socket。
pub(crate) async fn serve<F>(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: F,
    lifecycle: std::sync::Arc<Lifecycle>,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    use hyper_util::{rt::TokioIo, service::TowerToHyperService};
    let (graceful, _) = tokio::sync::watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break Ok(()),
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept(), if connections.len() < 1024 => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(e) => break Err(e) };
                // 自定义连接驱动仍须提供真实 socket 身份，供认证来源与可信代理校验使用。
                let app = app.clone().layer(axum::Extension(axum::extract::ConnectInfo(peer)));
                let conn = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app)).with_upgrades();
                let mut stopped=graceful.subscribe();
                connections.spawn(async move {
                    tokio::pin!(conn);
                    tokio::select! {
                        result = &mut conn => { let _ = result; },
                        _ = stopped.changed() => { conn.as_mut().graceful_shutdown(); let _ = conn.await; },
                    }
                });
            }
        }
    };
    drop(listener);
    let deadline = lifecycle.drain();
    // 协议驱动负责 graceful，JoinSet 负责期限后的真实连接回收。
    graceful.send_replace(true);
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout_at(deadline, drain).await.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        tracing::warn!(target: "memoswish::lifecycle", "HTTP connection drain exhausted the shared shutdown budget");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn repeated_shutdown_uses_first_deadline() {
        let lifecycle = Lifecycle::new(65);
        let first = lifecycle.drain();
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(lifecycle.drain(), first);
        assert_eq!(lifecycle.phase(), Phase::Draining);
    }
    #[tokio::test(start_paused = true)]
    async fn slow_body_and_keepalive_connections_are_closed_and_joined_at_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let life = std::sync::Arc::new(Lifecycle::new(1));
        life.set(Phase::Running);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (entered, received) = tokio::sync::oneshot::channel();
        let entered = std::sync::Arc::new(Mutex::new(Some(entered)));
        let app =
            axum::Router::new().route("/slow", axum::routing::post(move |_: axum::body::Bytes| async { "ok" })).route(
                "/pause",
                axum::routing::get(move || {
                    let entered = entered.clone();
                    async move {
                        if let Some(entered) = entered.lock().unwrap().take() {
                            let _ = entered.send(());
                        }
                        std::future::pending::<&'static str>().await
                    }
                }),
            );
        let serving = tokio::spawn(serve(
            listener,
            app,
            async {
                let _ = stopped.await;
            },
            life.clone(),
        ));
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\na").await.unwrap();
        let mut paused = tokio::net::TcpStream::connect(addr).await.unwrap();
        paused.write_all(b"GET /pause HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        received.await.unwrap();
        stop.send(()).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        serving.await.unwrap().unwrap();
        for stream in [&mut slow, &mut paused] {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
        }
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }
}
