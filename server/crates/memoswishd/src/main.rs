//! memoswishd：忆刷（Memoswish）服务端守护进程。
//!
//! ```text
//! memoswishd serve                  # 启动 HTTP API + /mcp（默认命令）
//! memoswishd mcp-stdio              # 以 stdio 方式运行 MCP
//! memoswishd token create --name x  # 为本地所有者（或 --email 指定用户）创建 API Token
//! memoswishd schema export          # 重新生成 protocol/schemas 与 protocol/fixtures
//! memoswishd seed                   # 写入演示卡组
//! memoswishd config                 # 打印生效配置（脱敏）
//! ```

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

use memoswishd::{Config, Daemon, maintenance};

#[derive(Parser)]
#[command(name = "memoswishd", version, about = concat!(env!("BRAND_EN_PRODUCT"), " (", env!("BRAND_ZH_PRODUCT"), ") server: HTTP API + embedded MCP server"))]
struct Cli {
    /// 配置文件路径（TOML）。
    #[arg(short, long, env = "MEMOSWISH_CONFIG", hide_env_values = true, global = true)]
    config: Option<PathBuf>,
    /// 覆盖监听地址。
    #[arg(long, global = true)]
    bind: Option<String>,
    /// 覆盖数据目录。
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// 覆盖数据库 URL（sqlite://... 或 postgres://...）。
    #[arg(long, global = true)]
    database_url: Option<String>,
    /// 部署配置覆盖。
    #[arg(long, global = true)]
    profile: Option<memoswishd::deployment::Profile>,
    /// 进程角色覆盖。
    #[arg(long, global = true)]
    role: Option<memoswishd::deployment::Role>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 显式恢复单个资产的块校验，不发现或调度后台工作。
    #[command(about = "Verify a referenced asset in resumable bounded blocks")]
    AssetVerify {
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "content")]
        surface: String,
        #[arg(long)]
        owner: Option<String>,
        #[arg(long, default_value_t = 64)]
        max_blocks: usize,
        #[arg(long, env = "MEMOSWISH_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },
    /// 停止写入者后，以受保护标准输入替换指定账户口令并撤销全部访问。
    #[command(about = "Recover an explicit account locally from protected stdin; all writers must be stopped")]
    PasswordRecover {
        #[arg(long)]
        user_id: String,
    },
    /// 启动 HTTP 服务（默认）。
    Serve,
    /// 使用直连管理凭据迁移并初始化共享安装，然后退出。
    Migrate,
    /// 通过 stdin/stdout 提供 MCP 服务。
    McpStdio {
        /// 以该 API Token 的身份运行；缺省为本地所有者（仅限本机使用）。
        #[arg(long, env = "MEMOSWISH_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },
    /// API Token 管理。
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// 导出 JSON Schema 与示例 fixture。
    Schema {
        #[command(subcommand)]
        action: SchemaAction,
    },
    /// 写入演示卡组（单用户模式的本地租户）。
    Seed,
    /// 打印生效配置。
    Config,
    #[cfg(feature = "oidc")]
    /// 将持久 OIDC 密文分批重加密为配置中的 active key，可中断后重跑。
    ReencryptKeys,
    /// 离线生成保留旧密钥的轮换配置，不覆盖源文件。
    RotateKeys {
        #[arg(long)]
        id: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// 只读统计内容孤儿；不执行迁移、初始化或清理，可在升级失败后运行。
    ContentOrphanReport,
    /// 根据观察到的修订版本重排已耗尽擦除，保留累计尝试和外部证据。
    #[command(about = "Requeue exhausted erasure work using the observed revision")]
    ErasureRequeue {
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        expected_revision: i64,
    },
    /// 按明确分类期限预览；apply 才删除候选正文与到期元数据。
    #[command(about = "Preview or apply a bounded category retention batch")]
    RetentionSweep {
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: i64,
        #[arg(long)]
        apply: bool,
    },
    /// 持久注册明确租户和策略；此命令不立即执行清理。
    #[command(about = "Register an explicit tenant retention policy for recurring maintenance")]
    RetentionRegister {
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        policy: PathBuf,
    },
    /// 只供隔离恢复；快照绑定及序列覆盖必须来自独立恢复记录。
    #[command(about = "Replay ordered suppressions into an isolated restored installation")]
    RestoreSuppressions {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        snapshot_sha256: String,
        #[arg(long)]
        after_sequence: u64,
        #[arg(long)]
        through_sequence: u64,
    },
    /// 冷备份工具专用：验证本地配置并保存含密钥的有效配置，不连接数据库。
    SnapshotConfig {
        #[arg(long)]
        output: PathBuf,
        /// 数据库包含 OIDC 持久凭据或在途身份流程时必须提供原始加密配置。
        #[arg(long)]
        require_oidc_key: bool,
        /// 保存 PostgreSQL + 本地资产安装配置。
        #[arg(long)]
        postgres: bool,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// 创建 API Token（明文只显示一次）。
    Create {
        #[arg(long)]
        name: String,
        /// 逗号分隔的 scope，例如 `content:write,tts:generate`；缺省 `*`。
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
        /// 有效期（天），缺省永久。
        #[arg(long)]
        ttl_days: Option<i64>,
        /// 为指定邮箱的用户创建（多租户模式）；缺省为本地所有者。
        #[arg(long)]
        email: Option<String>,
    },
}

#[derive(Subcommand)]
enum SchemaAction {
    /// 写入 `<out>/schemas/*.schema.json` 与 `<out>/fixtures/*.json`。
    Export {
        #[arg(long, default_value = "../protocol")]
        out: PathBuf,
    },
}

fn init_tracing() {
    // 日志统一写 stderr：stdio MCP 模式下 stdout 专用于协议消息。
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info")))
        // SDK 的请求/响应诊断含原始负载，禁止 RUST_LOG 覆盖此安全过滤器。
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(
            tracing_subscriber::filter::filter_fn(|metadata| {
                memoswishd::deployment::diagnostic_target_allowed(metadata.target())
            }),
        ))
        .init();
}

fn main() -> anyhow::Result<()> {
    Config::reject_legacy_environment()?;
    init_tracing();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion) =>
        {
            error.print()?;
            return Ok(());
        }
        Err(_) => anyhow::bail!("invalid command line; use --help for supported options"),
    };
    let mut cfg = Config::load(cli.config.as_deref())?;
    if let Some(b) = cli.bind {
        cfg.bind = b;
    }
    if let Some(d) = cli.data_dir {
        cfg.data_dir = d;
    }
    if let Some(u) = cli.database_url {
        cfg.database_url = Some(u);
    }

    if let Some(profile) = cli.profile {
        cfg.profile = profile;
    }
    if let Some(role) = cli.role {
        cfg.role = role;
    }
    let command = cli.command.unwrap_or(Command::Serve);
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(run(cfg, command));
    // 异步收尾已限时排空；目录锁持续到内核关闭进程描述符。
    runtime.shutdown_timeout(std::time::Duration::ZERO);
    result
}

async fn run(cfg: Config, command: Command) -> anyhow::Result<()> {
    match command {
        Command::AssetVerify { key, surface, owner, max_blocks, token } => {
            let result =
                maintenance::verify_asset(&cfg, token.as_deref(), &key, &surface, owner.as_deref(), max_blocks).await;
            println!("{}", serde_json::to_string(&result?)?);
            Ok(())
        }
        Command::PasswordRecover { user_id } => {
            use std::io::{IsTerminal, Read};
            anyhow::ensure!(!std::io::stdin().is_terminal(), "password recovery requires protected piped stdin");
            let mut bytes = Vec::new();
            std::io::stdin().take(1026).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 1025, "password input exceeds recovery budget");
            let text = String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("password must be UTF-8"))?;
            let password = text.strip_suffix('\n').unwrap_or(&text);
            maintenance::recover_password(&cfg, &user_id, password).await?;
            println!("Password replaced; all access revoked; email verification required");
            Ok(())
        }
        Command::Serve => serve(cfg).await,
        Command::Migrate => memoswishd::migrate_until(cfg, shutdown_signal()).await,
        Command::McpStdio { token } => mcp_stdio(cfg, token).await,
        Command::Token { action: TokenAction::Create { name, scopes, ttl_days, email } } => {
            let st = Daemon::start(Config { seed_demo: false, ..cfg }).await?;
            let created = st.create_cli_token(&name, scopes, ttl_days, email.as_deref()).await;
            st.shutdown().await;
            let created = created?;
            eprintln!(
                "Created API token `{}` (id {}) for tenant {}.",
                created.record.name, created.record.id, created.record.tenant_id
            );
            eprintln!("Scopes: {}. Store it now; it will not be shown again.", created.record.scopes.join(","));
            println!("{}", created.plaintext);
            Ok(())
        }
        Command::Schema { action: SchemaAction::Export { out } } => {
            let n = memoswish_protocol::export_contracts(&out)?;
            eprintln!("Wrote {n} contract files to {}", out.display());
            Ok(())
        }
        Command::Seed => {
            let st = Daemon::start(Config { seed_demo: false, ..cfg }).await?;
            let result = st.seed().await;
            st.shutdown().await;
            let n = result?;
            eprintln!("Seeded {n} demo cards.");
            Ok(())
        }
        #[cfg(feature = "oidc")]
        Command::ReencryptKeys => {
            let app = Daemon::start(cfg).await?;
            let result = app.reencrypt_keys().await;
            app.shutdown().await;
            let changed = result?;
            println!("Re-encrypted records: {changed}");
            Ok(())
        }
        Command::RotateKeys { id, output } => maintenance::rotate(cfg, &id, &output),
        Command::Config => {
            cfg.validate()?;
            println!("{}", toml::to_string_pretty(&cfg.redacted())?);
            Ok(())
        }
        Command::ErasureRequeue { job_id, expected_revision } => {
            maintenance::requeue_erasure(&cfg, &job_id, expected_revision).await?;
            println!("Erasure operation requeued");
            Ok(())
        }
        Command::ContentOrphanReport => {
            let report = maintenance::content_orphan_report(&cfg).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::RetentionSweep { tenant_id, policy, limit, apply } => {
            let report = maintenance::retention_sweep(&cfg, &tenant_id, &policy, limit, apply).await?;
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        }
        Command::RetentionRegister { tenant_id, policy } => {
            maintenance::register_retention(&cfg, &tenant_id, &policy).await?;
            println!("Retention policy registered; maintenance will process bounded pages");
            Ok(())
        }
        Command::RestoreSuppressions { input, snapshot_sha256, after_sequence, through_sequence } => {
            maintenance::restore_suppressions(&cfg, &input, &snapshot_sha256, after_sequence, through_sequence).await?;
            println!(
                "Suppression batch committed; keep restore isolated until external cleanup and verification finish"
            );
            Ok(())
        }
        Command::SnapshotConfig { output, require_oidc_key, postgres } => {
            maintenance::write_profile_config(cfg, &output, require_oidc_key, postgres)
        }
    }
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let bind = cfg.bind.clone();
    anyhow::ensure!(cfg.role != memoswishd::deployment::Role::Migrator, "use the migrate command for migrator role");
    let (signal, received) = tokio::sync::watch::channel(false);
    let signals = tokio::spawn(async move {
        shutdown_signal().await;
        signal.send_replace(true);
    });
    let startup_signal = received.clone();
    let daemon = Daemon::start_until(cfg, async move { wait_signal(startup_signal).await }).await?;
    if !daemon.config().role.serves() {
        let result = daemon.run_role(wait_signal(received)).await;
        signals.abort();
        return result;
    }
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(error) => {
            daemon.shutdown().await;
            return Err(error).with_context(|| format!("cannot bind {bind}"));
        }
    };
    let result = daemon.serve_http(listener, None, wait_signal(received)).await;
    signals.abort();
    result
}

async fn mcp_stdio(cfg: Config, token: Option<String>) -> anyhow::Result<()> {
    let (signal, received) = tokio::sync::watch::channel(false);
    let signals = tokio::spawn(async move {
        shutdown_signal().await;
        signal.send_replace(true);
    });
    let startup_signal = received.clone();
    let daemon = Daemon::start_until(cfg, wait_signal(startup_signal)).await?;
    let result = daemon
        .serve_stdio_with_shutdown(
            token.as_deref(),
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
            wait_signal(received),
        )
        .await;
    signals.abort();
    result
}

async fn wait_signal(mut receiver: tokio::sync::watch::Receiver<bool>) {
    let _ = receiver.wait_for(|value| *value).await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod ownership_report_tests {
    use super::*;

    #[tokio::test]
    async fn orphan_report_does_not_migrate_or_initialize_an_invalid_installation() {
        let root = std::env::temp_dir().join(format!("memoswish-orphan-report-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("legacy.db");
        let url = format!("sqlite://{}", path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(url.parse::<sqlx::sqlite::SqliteConnectOptions>().unwrap().create_if_missing(true))
            .await
            .unwrap();
        let full = sqlx::migrate!("../memoswish-storage/migrations/sqlite");
        let old = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(full.iter().filter(|m| m.version <= 16).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        old.run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO decks VALUES('orphan','missing','PRIVATE_SENTINEL','','en','[]','2026-11-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let entries = || {
            let mut names: Vec<_> = std::fs::read_dir(&root).unwrap().map(|entry| entry.unwrap().file_name()).collect();
            names.sort();
            names
        };
        let before = entries();
        run(
            Config { database_url: Some(url.clone()), data_dir: root.clone(), ..Default::default() },
            Command::ContentOrphanReport,
        )
        .await
        .unwrap();
        assert_eq!(entries(), before, "read-only report must not initialize installation files");
        assert!(!root.join("jwt_secret").exists());
        assert!(!root.join("assets").exists());
        let report = memoswish_storage::ownership::content_orphan_report(&url).await.unwrap();
        assert_eq!(report.iter().find(|r| r.category == "decks_missing_tenant").unwrap().row_count, 1);
        assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE_SENTINEL"));
        let version: i64 =
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(&pool).await.unwrap();
        assert_eq!(version, 16);
        assert!(sqlx::query("SELECT * FROM deleted_card_ids").execute(&pool).await.is_err());
        pool.close().await;
        let missing = root.join("does-not-exist.db");
        assert!(
            memoswish_storage::ownership::content_orphan_report(&format!("sqlite://{}", missing.display()))
                .await
                .is_err()
        );
        assert!(!missing.exists());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
