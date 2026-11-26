//! 受保护的安装生命周期；传输退出与宿主取消共享现有排空顺序。

use std::future::Future;

use anyhow::Context;

use memoswish_application::Services;
use memoswish_core::Principal;
use memoswish_protocol::ServerInfo;

use crate::{app::AppState, config::Config};

/// 一个进程中的唯一安装。宿主须等待关闭完成后再停止 Tokio 运行时。
#[must_use = "the daemon must be served or shut down"]
pub struct Daemon {
    state: Option<AppState>,
    probes: Option<crate::health::ProbeServer>,
}

impl Daemon {
    /// 在迁移、恢复或任何安装写入之前取得进程生命周期写锁。
    /// 不安装全局 tracing subscriber，也不创建运行时。
    pub async fn start(config: Config) -> anyhow::Result<Self> {
        Self::start_until(config, std::future::pending()).await
    }

    /// 启动期间也接受关闭；取消等待由独立所有者完成有界收尾。
    pub async fn start_until<F>(config: Config, shutdown: F) -> anyhow::Result<Self>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let _cancel_on_drop = CancelOnDrop(Some(cancel));
        tokio::spawn(Self::start_owned(config, async move {
            tokio::select! { _ = shutdown => {}, _ = cancelled => {} }
        }))
        .await?
    }

    async fn start_owned<F>(config: Config, shutdown: F) -> anyhow::Result<Self>
    where
        F: Future<Output = ()> + Send,
    {
        config.validate()?;
        config.preflight_key()?;
        if config.profile == crate::deployment::Profile::Embedded {
            crate::directory_lock::acquire(&config.data_dir)?;
        }
        let health = crate::health::Health::new(&config);
        let probes = crate::health::ProbeServer::start(&config, health.clone()).await?;
        tokio::pin!(shutdown);
        let result = tokio::select! {
            biased;
            _ = &mut shutdown => Err(anyhow::anyhow!("startup cancelled")),
            result = AppState::assemble_with_health(config, health.clone()) => result,
        };
        let state = match result {
            Ok(state) => state,
            Err(error) => {
                health.lifecycle.set(crate::lifecycle::Phase::Failed);
                probes.shutdown().await;
                return Err(error);
            }
        };
        state.health.attach(&state)?;
        let daemon = Self { state: Some(state), probes: Some(probes) };
        let st = daemon.state.as_ref().expect("daemon state is available");
        if st.config.role == crate::deployment::Role::Migrator {
            health.lifecycle.set(crate::lifecycle::Phase::Running);
        }
        let result = tokio::select! {
            biased;
            _ = &mut shutdown => Err(anyhow::anyhow!("startup cancelled")),
            result = st.initialize() => result,
        };
        if let Err(error) = result {
            health.lifecycle.set(crate::lifecycle::Phase::Failed);
            daemon.shutdown().await;
            return Err(error);
        }
        health.lifecycle.set(crate::lifecycle::Phase::Running);
        Ok(daemon)
    }

    #[cfg(test)]
    async fn initialize_with<F, Fut>(state: AppState, initialize: F) -> anyhow::Result<Self>
    where
        F: FnOnce(AppState) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        // 首次后台写入或恢复之前建立所有者；错误与取消都通过同一 Drop 关闭准入并排空。
        state.health.attach(&state)?;
        let daemon = Self { state: Some(state), probes: None };
        let st = daemon.state.as_ref().expect("daemon state is available");
        if let Err(error) = initialize(st.clone()).await {
            st.health.lifecycle.set(crate::lifecycle::Phase::Failed);
            return Err(error);
        }
        st.health.lifecycle.set(crate::lifecycle::Phase::Running);
        Ok(daemon)
    }

    /// 核心应用门面；扩展仍须自行校验其调用主体及权限。
    pub fn services(&self) -> &Services {
        &self.state.as_ref().expect("daemon state is available").services
    }

    /// 显式验证复用同一应用端口及凭据域，不取得恢复工作的调度权限。
    pub async fn verify_asset(
        &self,
        token: Option<&str>,
        key: &str,
        surface: &str,
        owner: Option<&str>,
        max_blocks: usize,
    ) -> memoswish_core::CoreResult<memoswish_core::asset_read::ReadManifest> {
        let st = self.state.as_ref().expect("daemon state is available");
        let principal = st.services.auth.authenticate(token).await?;
        st.services.auth.require_privacy_collection(&principal).await?;
        memoswish_application::asset_delivery::verify(
            st.repo.as_ref(),
            st.store.as_ref(),
            &principal,
            key,
            surface,
            owner,
            max_blocks,
        )
        .await
    }

    /// 配置只读视图；日志应使用 Config::redacted。
    pub fn config(&self) -> &Config {
        &self.state.as_ref().expect("daemon state is available").config
    }

    /// 与核心 HTTP 端点相同的能力摘要。
    pub fn server_info(&self) -> ServerInfo {
        self.state.as_ref().expect("daemon state is available").server_info()
    }

    /// 用核心路由服务宿主监听器；可选宿主路由仅挂载于 /extensions。
    /// 核心路由保留原有认证、中间件与错误映射。
    pub async fn serve_http<F>(
        self,
        listener: tokio::net::TcpListener,
        extensions: Option<axum::Router>,
        shutdown: F,
    ) -> anyhow::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        anyhow::ensure!(self.config().role.serves(), "this role cannot serve business transports");
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        // 宿主取消等待时仅请求关闭，核心任务继续拥有 HTTP 退出与后续排空。
        let _cancel_on_drop = CancelOnDrop(Some(cancel));
        tokio::spawn(self.run_http(listener, extensions, async move {
            tokio::select! {
                _ = shutdown => {},
                _ = cancelled => {},
            }
        }))
        .await?
    }

    async fn run_http<F>(
        self,
        listener: tokio::net::TcpListener,
        extensions: Option<axum::Router>,
        shutdown: F,
    ) -> anyhow::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let st = self.state.as_ref().expect("daemon state is available").clone();
        let info = st.server_info();
        let maintenance = tokio::spawn(maintenance_loop(st.clone()));
        let mut app = crate::api::router(st.clone());
        if let Some(routes) = extensions {
            let routes = crate::api::instrument(routes, st.clone());
            app = app.nest("/extensions", routes);
        }
        tracing::info!(target: "memoswish::runtime",
            addr = %listener.local_addr()?,
            mode = ?info.mode,
            features = ?info.features,
            tts = ?info.tts_engines,
            "memoswishd listening (HTTP API + /mcp)"
        );
        let stopping = st.clone();
        let result = crate::lifecycle::serve(
            listener,
            app,
            async move {
                shutdown.await;
                stopping.health.lifecycle.drain();
                stopping.services.operations.close();
                stopping.services.auth.close_password_work();
            },
            st.health.lifecycle.clone(),
        )
        .await;
        st.services.operations.close();
        st.services.auth.close_password_work();
        // 调度器只停止发现；已经登记的任务继续拥有心跳和补偿。
        let _ = maintenance.await;
        self.shutdown().await;
        result?;
        tracing::info!(target: "memoswish::runtime", "memoswishd stopped");
        Ok(())
    }

    /// worker/maintenance 无业务监听器，串行处理既有有界页并沿用 SQL fence。
    pub async fn run_role<F>(self, shutdown: F) -> anyhow::Result<()>
    where
        F: Future<Output = ()> + Send,
    {
        use crate::deployment::Role;
        anyhow::ensure!(
            matches!(self.config().role, Role::Worker | Role::Maintenance),
            "run_role requires worker or maintenance"
        );
        let st = self.state.as_ref().expect("daemon state is available").clone();
        tokio::select! {
            _ = shutdown => {},
            _ = maintenance_loop(st.clone()) => {},
        }
        st.health.lifecycle.drain();
        st.services.operations.close();
        st.services.auth.close_password_work();
        self.shutdown().await;
        Ok(())
    }

    /// 核心负责可信本机或 Token 身份构造，以及 EOF、握手失败后的排空。
    pub async fn serve_stdio<R, W>(self, token: Option<&str>, reader: R, writer: W) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        self.serve_stdio_with_shutdown(token, reader, writer, std::future::pending()).await
    }

    /// stdio 传输与信号、宿主取消共享关闭所有者。
    pub async fn serve_stdio_with_shutdown<R, W, F>(
        self,
        token: Option<&str>,
        reader: R,
        writer: W,
        shutdown: F,
    ) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        anyhow::ensure!(self.config().role.serves(), "this role cannot serve business transports");
        let token = token.map(str::to_owned);
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        let _cancel_on_drop = CancelOnDrop(Some(cancel));
        tokio::spawn(self.run_stdio(token, reader, writer, async move {
            tokio::select! { _ = shutdown => {}, _ = cancelled => {} }
        }))
        .await?
    }

    async fn run_stdio<R, W, F>(
        mut self,
        token: Option<String>,
        reader: R,
        writer: W,
        cancelled: F,
    ) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
        W: tokio::io::AsyncWrite + Send + Unpin + 'static,
        F: Future<Output = ()> + Send,
    {
        let st = self.state.as_ref().expect("daemon state is available");
        tokio::pin!(cancelled);
        // 身份读取也属于传输生命周期，不能在等待数据库期间忽略宿主关闭。
        let principal = tokio::select! {
            biased;
            _ = &mut cancelled => None,
            result = async {
                match token.as_deref() {
                    Some(token) => st.services.auth.authenticate(Some(token)).await,
                    None => st.services.auth.authenticate_local_stdio().await,
                }
            } => Some(result),
        };
        let Some(principal) = principal else {
            self.shutdown().await;
            return Ok(());
        };
        let principal = match principal {
            Ok(principal) => principal,
            Err(error) => {
                self.shutdown().await;
                return Err(error.into());
            }
        };
        tracing::info!(target: "memoswish::runtime", tenant = %principal.tenant_id, via = %principal.via, "mcp stdio server ready");
        let maintenance = tokio::spawn(maintenance_loop(st.clone()));
        let result = serve_stdio_until(st, &principal, reader, writer, async {
            cancelled.await;
        })
        .await;
        let _ = maintenance.await;
        self.state.take();
        if let Some(probes) = self.probes.take() {
            probes.shutdown().await;
        }
        result
    }

    /// 可信本机 CLI 创建 Token；沿用当前成员资格与认证世代检查。
    pub async fn create_cli_token(
        &self,
        name: &str,
        scopes: Vec<String>,
        ttl_days: Option<i64>,
        email: Option<&str>,
    ) -> anyhow::Result<memoswish_auth::CreatedToken> {
        let st = self.state.as_ref().expect("daemon state is available");
        let principal = match email {
            None => Principal::local_owner("cli"),
            Some(e) => {
                let u = st.repo.find_user_by_email(e).await?.with_context(|| format!("no user with email {e}"))?;
                let membership = st
                    .repo
                    .memberships(&u.id)
                    .await?
                    .into_iter()
                    .find(|m| m.tenant_id == u.tenant_id)
                    .context("membership no longer exists")?;
                let generation = st.repo.account_generation(&u.id).await?;
                Principal {
                    tenant_id: u.tenant_id,
                    user_id: u.id,
                    role: u.role,
                    scopes: None,
                    via: "cli".into(),
                    session_access_hash: None,
                    auth_generation: Some(generation),
                    membership_generation: Some(membership.generation),
                    legacy_issued_at: None,
                }
            }
        };
        Ok(st.services.auth.create_api_token(&principal, name, scopes, ttl_days).await?)
    }

    /// CLI 演示数据命令沿用核心实现。
    pub async fn seed(&self) -> anyhow::Result<usize> {
        anyhow::ensure!(
            self.config().profile == crate::deployment::Profile::Embedded,
            "demo seed requires embedded profile"
        );
        crate::seed::seed(self.state.as_ref().expect("daemon state is available"), &Principal::local_owner("cli")).await
    }

    /// CLI 密文轮换沿用已配置的 OIDC 服务。
    #[cfg(feature = "oidc")]
    pub async fn reencrypt_keys(&self) -> anyhow::Result<u64> {
        let service = self
            .state
            .as_ref()
            .expect("daemon state is available")
            .oidc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OIDC must be enabled for re-encryption"))?;
        Ok(service.reencrypt().await?)
    }

    /// 先关闭应用准入，再以原有共享预算排空应用任务与 PUT。
    pub async fn shutdown(mut self) {
        if let Some(st) = self.state.take() {
            st.health.lifecycle.drain();
            st.services.operations.close();
            st.services.auth.close_password_work();
            let probes = self.probes.take();
            // 取消等待只丢弃 JoinHandle，不重置已经开始的共享关闭预算。
            if let Err(error) = tokio::spawn(async move {
                drain_background(&st).await;
                if let Some(probes) = probes {
                    probes.shutdown().await;
                }
            })
            .await
            {
                tracing::error!(target: "memoswish::runtime", %error, "Daemon shutdown task failed");
            }
        }
    }
}

// 内部测试需要多次构建状态，但仍共用生产初始化的取消与失败保护。
#[cfg(test)]
pub(crate) async fn build_test_state(config: Config) -> anyhow::Result<AppState> {
    let state = AppState::assemble(config).await?;
    let mut daemon = Daemon::initialize_with(state, |st| async move { st.initialize().await }).await?;
    Ok(daemon.state.take().expect("daemon state is available"))
}

// 测试删除目录前必须证明任务已结束，不能把生产关闭预算耗尽当成完成。
#[cfg(test)]
pub(crate) async fn drain_test_state(st: &AppState) {
    drain_background(st).await;
    st.services.operations.wait().await;
    st.services.auth.wait_for_password_work().await;
    if let Some(mail) = &st.password_mail {
        mail.wait().await;
    }
    // 虚拟时钟可先于真实 I/O 跨过预算；目录删除必须等待 PUT 及补偿实际结束。
    st.put_tasks.wait().await;
    assert!(st.put_tasks.shutdown().await, "test cleanup still has active object writes");
}

// 同一目录可能经历重启或双副本；所有仍持有任务的状态都须在删除前排空。
#[cfg(test)]
pub(crate) async fn cleanup_test_app(dir: impl AsRef<std::path::Path>, states: &[&AppState]) {
    assert!(!states.is_empty(), "test cleanup requires the application task owners");
    for st in states {
        st.health.lifecycle.drain();
        st.services.operations.close();
        st.services.auth.close_password_work();
    }
    for st in states {
        drain_test_state(st).await;
    }
    tokio::fs::remove_dir_all(dir).await.unwrap();
}

#[cfg(all(test, feature = "sqlite", unix))]
#[path = "runtime_tests.rs"]
mod tests;

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(st) = self.state.take() {
            st.health.lifecycle.drain();
            st.services.operations.close();
            st.services.auth.close_password_work();
            let probes = self.probes.take();
            // 宿主提前丢弃或取消服务时，运行时继续拥有收尾；安装锁始终不释放。
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    drain_background(&st).await;
                    if let Some(probes) = probes {
                        probes.shutdown().await;
                    }
                });
            } else {
                st.put_tasks.close();
                tracing::warn!(target: "memoswish::runtime", "Daemon dropped without a running runtime; background drain could not run");
            }
        }
    }
}

struct CancelOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(cancel) = self.0.take() {
            let _ = cancel.send(());
        }
    }
}

#[cfg(test)]
pub(crate) async fn serve_stdio<R, W>(st: &AppState, principal: &Principal, reader: R, writer: W) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
    W: tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    serve_stdio_until(st, principal, reader, writer, std::future::pending()).await
}

async fn serve_stdio_until<R, W, F>(
    st: &AppState,
    principal: &Principal,
    reader: R,
    writer: W,
    stopped: F,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
    W: tokio::io::AsyncWrite + Send + Unpin + 'static,
    F: Future<Output = ()> + Send,
{
    let result = tokio::select! {
        biased;
        _ = stopped => Ok(()),
        result = memoswish_mcp::stdio::serve(&st.mcp, principal, reader, writer) => result,
    };
    // EOF、握手失败、服务返回错误和宿主取消都不能跳过应用层收尾。
    drain_background(st).await;
    result?;
    Ok(())
}

pub(crate) async fn drain_background(st: &AppState) {
    if let Some(mail) = &st.password_mail {
        mail.close();
    }
    st.services.operations.close();
    st.services.auth.close_password_work();
    // 应用任务和底层 PUT 共用现有关闭预算，不叠加新的超时窗口。
    let deadline = st.health.lifecycle.drain();
    if tokio::time::timeout_at(deadline, st.services.operations.wait()).await.is_err() {
        tracing::warn!(target: "memoswish::runtime",
            "Application shutdown drain timed out; durable import, speech and explanation responsibility remains pending"
        );
    }
    if tokio::time::timeout_at(deadline, st.services.auth.wait_for_password_work()).await.is_err() {
        tracing::warn!(target: "memoswish::runtime",
            "Password work drain exhausted the shared shutdown budget; blocking computations retain capacity until completion"
        );
    }
    if let Some(mail) = &st.password_mail
        && tokio::time::timeout_at(deadline, mail.wait()).await.is_err()
    {
        tracing::warn!(target: "memoswish::runtime", "SMTP shutdown drain exhausted shared shutdown budget; explicit resend required");
    }
    st.put_tasks.close();
    if tokio::time::timeout_at(deadline, st.put_tasks.shutdown()).await.is_err() {
        tracing::warn!(target: "memoswish::runtime", "Object PUT shutdown drain exhausted the shared shutdown budget");
    }
    if st.health.lifecycle.phase() != crate::lifecycle::Phase::Failed {
        st.health.lifecycle.set(crate::lifecycle::Phase::Stopped);
    }
}

#[cfg(all(test, feature = "postgres", feature = "s3", feature = "redis"))]
#[path = "deployment_tests.rs"]
mod deployment_tests;

async fn maintenance_loop(st: AppState) {
    crate::maintenance_scheduler::run_loop(st).await;
}
