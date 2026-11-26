//! 最终组合的纯校验；不得创建文件、连接数据库或联系 provider。
use super::Config;

fn seconds(value: u64) -> bool {
    value > 0
        && value <= i64::MAX as u64 / 1_000
        && std::time::Instant::now().checked_add(std::time::Duration::from_secs(value)).is_some()
}

fn endpoint(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
    })
}

fn listener_address(value: &str) -> bool {
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && port.parse::<u16>().is_ok()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn listeners_conflict(business: &str, health: &str) -> bool {
    let port = business.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
    if port == Some(0) {
        return false;
    }
    if business.eq_ignore_ascii_case(health) {
        return true;
    }
    match (business.parse::<std::net::SocketAddr>(), health.parse::<std::net::SocketAddr>()) {
        (Ok(a), Ok(b)) => {
            a.port() == b.port()
                && a.is_ipv4() == b.is_ipv4()
                && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
        }
        _ => false,
    }
}

pub(super) fn reject_placeholder(field: &str, value: &str) -> anyhow::Result<()> {
    let normalized = value.trim().to_ascii_lowercase();
    let placeholder = normalized == "sk-..."
        || ["replace-with", "replace-me", "change-me", "changeme"].iter().any(|prefix| normalized.starts_with(prefix));
    anyhow::ensure!(!placeholder, "{field} contains a placeholder credential");
    Ok(())
}

fn validate_url_password(field: &str, url: &url::Url) -> anyhow::Result<()> {
    let check = |password: &str| {
        if field == "database_url.password" {
            anyhow::ensure!(
                !matches!(password, "secret" | "pass" | "memoswish"),
                "{field} contains a placeholder credential"
            );
        }
        reject_placeholder(field, password)
    };
    if let Some(password) = url.password() {
        check(&percent_encoding::percent_decode_str(password).decode_utf8_lossy())?;
    }
    for (_, password) in url.query_pairs().filter(|(key, _)| key == "password") {
        check(&password)?;
    }
    Ok(())
}

fn validate_database_options(database: &str) -> anyhow::Result<()> {
    let kind =
        memoswish_storage::DatabaseKind::from_url(database).map_err(|_| anyhow::anyhow!("unsupported database URL"))?;
    match kind {
        memoswish_storage::DatabaseKind::Sqlite => {
            #[cfg(feature = "sqlite")]
            database
                .parse::<sqlx::sqlite::SqliteConnectOptions>()
                .map_err(|_| anyhow::anyhow!("invalid SQLite connection options"))?;
            anyhow::ensure!(cfg!(feature = "sqlite"), "database backend requires an unavailable feature");
        }
        memoswish_storage::DatabaseKind::Postgres => {
            let url = url::Url::parse(database).map_err(|_| anyhow::anyhow!("invalid database URL"))?;
            #[cfg(not(feature = "postgres"))]
            validate_url_password("database_url.password", &url)?;
            // 与锁定 SQLx 0.8.6 的参数集合对齐；原生解析器会在 WARN 输出未知名称及值。
            anyhow::ensure!(
                url.query_pairs().all(|(key, _)| {
                    matches!(
                        key.as_ref(),
                        "sslmode"
                            | "ssl-mode"
                            | "sslrootcert"
                            | "ssl-root-cert"
                            | "ssl-ca"
                            | "sslcert"
                            | "ssl-cert"
                            | "sslkey"
                            | "ssl-key"
                            | "statement-cache-capacity"
                            | "host"
                            | "hostaddr"
                            | "port"
                            | "dbname"
                            | "user"
                            | "password"
                            | "application_name"
                            | "options"
                    ) || (key.starts_with("options[") && key.ends_with(']') && key.len() > "options[]".len())
                }),
                "unsupported PostgreSQL connection parameter"
            );
            // 只解析、不建连接；原生 pgpass 读取的内部诊断也不得绕过安全错误边界。
            #[cfg(feature = "postgres")]
            {
                use sqlx::ConnectOptions;
                let options = tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                    database.parse::<sqlx::postgres::PgConnectOptions>()
                })
                .map_err(|_| anyhow::anyhow!("invalid PostgreSQL connection options"))?;
                // SQLx 已按 URL、PGPASSWORD、pgpass 的顺序选定密码，没有公开的密码 getter。
                // 导出前替换用户名和主机，避免 SQLx 将解码后的特殊字符直接拼入 URL。
                let resolved = options.username("user").host("localhost").to_url_lossy();
                validate_url_password("database_url.password", &resolved)?;
            }
            anyhow::ensure!(cfg!(feature = "postgres"), "database backend requires an unavailable feature");
        }
    }
    Ok(())
}

impl Config {
    fn validate_secret_fields(&self) -> anyhow::Result<()> {
        let s3 = &self.object_store.s3;
        for (field, value) in [
            ("jwt_secret", self.jwt_secret.as_deref()),
            ("object_store.s3.access_key_id", Some(s3.access_key_id.as_str())),
            ("object_store.s3.secret_access_key", Some(s3.secret_access_key.as_str())),
            ("ai.api_key", self.ai.api_key.as_deref()),
            ("smtp.password", Some(self.smtp.password.as_str())),
            ("oidc.encryption_key", Some(self.oidc.encryption_key.as_str())),
        ] {
            if let Some(value) = value {
                reject_placeholder(field, value)?;
            }
        }
        for key in self.jwt_keys.values() {
            reject_placeholder("jwt_keys.secret", &key.secret)?;
        }
        for key in self.oidc.encryption_keys.values() {
            reject_placeholder("oidc.encryption_keys.secret", &key.secret)?;
        }
        for provider in &self.oidc.providers {
            reject_placeholder("oidc.providers.client_secret", &provider.client_secret)?;
            reject_placeholder("oidc.providers.apple_private_key", &provider.apple_private_key)?;
        }
        for provider in &self.tts.http {
            if let Some(key) = &provider.api_key {
                reject_placeholder("tts.http.api_key", key)?;
            }
        }
        if let Some(url) = self.admission.redis_url.as_deref().and_then(|value| url::Url::parse(value).ok()) {
            validate_url_password("admission.redis_url.password", &url)?;
        }
        Ok(())
    }

    pub(crate) fn validate_runtime_values(&self) -> anyhow::Result<()> {
        self.validate_secret_fields()?;
        self.feed.validate()?;
        anyhow::ensure!(listener_address(&self.bind), "invalid business listener address");
        anyhow::ensure!(listener_address(&self.health_bind), "invalid health listener address");
        anyhow::ensure!(
            !self.role.serves() || !listeners_conflict(&self.bind, &self.health_bind),
            "health and business listeners require distinct addresses"
        );
        anyhow::ensure!(!self.data_dir.as_os_str().is_empty(), "data_dir must not be empty");
        anyhow::ensure!(seconds(self.jwt_ttl_secs), "invalid JWT lifetime");
        let database = self.database_url();
        anyhow::ensure!(
            !database.trim().is_empty() && database.trim() == database && !database.chars().any(char::is_control),
            "invalid database URL"
        );
        validate_database_options(&database)?;
        anyhow::ensure!(self.db_max_connections != Some(0), "db_max_connections must be positive");
        let c = &self.object_store;
        anyhow::ensure!(
            (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&c.max_concurrent_puts),
            "object_store.max_concurrent_puts exceeds supported bounds"
        );
        anyhow::ensure!(
            c.put_admission_timeout_ms > 0
                && c.put_admission_timeout_ms <= i64::MAX as u64
                && seconds(c.put_shutdown_timeout_secs),
            "invalid object PUT budgets"
        );
        anyhow::ensure!((1..=604800).contains(&c.s3.presign_ttl_secs), "invalid S3 signing lifetime");
        if c.backend == "s3" {
            anyhow::ensure!(
                !c.s3.access_key_id.trim().is_empty() && !c.s3.secret_access_key.trim().is_empty(),
                "S3 requires explicit credentials"
            );
        }
        let mut ids = std::collections::HashSet::from(["unconfigured", "placeholder"]);
        if self.tts.auto_detect_espeak || self.tts.default_engine == "espeak-ng" {
            ids.insert("espeak-ng");
        }
        for c in &self.tts.commands {
            anyhow::ensure!(
                !c.program.trim().is_empty()
                    && !c.program.contains('\0')
                    && !c.default_voice.trim().is_empty()
                    && !c.default_voice.contains('\0')
                    && c.args.iter().all(|arg| !arg.contains('\0'))
                    && seconds(c.timeout_secs),
                "invalid command TTS configuration"
            );
        }
        for c in &self.tts.http {
            anyhow::ensure!(
                endpoint(&c.endpoint)
                    && !c.model.trim().is_empty()
                    && !c.default_voice.trim().is_empty()
                    && seconds(c.timeout_secs),
                "invalid HTTP TTS configuration"
            );
        }
        for id in self.tts.commands.iter().map(|c| c.id.as_str()).chain(self.tts.http.iter().map(|c| c.id.as_str())) {
            anyhow::ensure!(
                memoswish_core::assets::validate_asset_id(id).is_ok() && ids.insert(id),
                "invalid or duplicate TTS engine ID"
            );
        }
        anyhow::ensure!(ids.contains(self.tts.default_engine.as_str()), "configured TTS engine is unavailable");
        if let Some(base) = &self.ai.base_url {
            anyhow::ensure!(
                endpoint(base)
                    && self.ai.api_key.as_ref().is_some_and(|k| !k.trim().is_empty())
                    && !self.ai.model.trim().is_empty(),
                "incomplete AI provider configuration"
            );
        }
        if self.ai.api_key.is_some() {
            anyhow::ensure!(self.ai.base_url.is_some(), "incomplete AI provider configuration");
        }
        if let Some(policy) = &self.ai.budget {
            // 安装前复用领域范围与溢出校验；诊断不携带策略身份或凭据。
            policy
                .validate(chrono::Utc::now().timestamp_millis())
                .map_err(|_| anyhow::anyhow!("invalid or expired explanation budget configuration"))?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing::instrument::WithSubscriber;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn invalid_native_database_options_and_unknown_parameters_precede_all_effects_without_secret_logs() {
        let database = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sentinel = "S26B_CREDENTIAL_SENTINEL";
        let parameter = "S26B_PARAMETER_SENTINEL";
        let postgres = format!("postgres://user:{sentinel}@{}/db", database.local_addr().unwrap());
        for level in ["info,sqlx=warn,tower_http=info", "trace"] {
            let capture = Capture::default();
            let writer = capture.clone();
            // 不使用产品 target 过滤器，证明库预检本身不会向宿主日志输出原始参数。
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(level)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            async {
                for url in [
                    "sqlite::memory:?mode=invalid".into(),
                    format!("sqlite::memory:?mode={sentinel}"),
                    format!("{postgres}?sslmode=invalid"),
                    format!("{postgres}?sslmode={sentinel}"),
                    format!("{postgres}?passwrod={sentinel}"),
                    format!("{postgres}?{parameter}={sentinel}"),
                    format!("{postgres}?%53%32%36%42_PARAMETER_SENTINEL={sentinel}"),
                    format!("{postgres}?options[{parameter}={sentinel}"),
                ] {
                    for existing in [false, true] {
                        let root =
                            std::env::temp_dir().join(format!("s26b-db-invalid-{}", memoswish_core::ids::new_id()));
                        let key = "original-synthetic-secret-with-32-bytes";
                        if existing {
                            std::fs::create_dir(&root).unwrap();
                            std::fs::write(root.join("jwt_secret"), key).unwrap();
                        }
                        let mut cfg =
                            Config { data_dir: root.clone(), database_url: Some(url.clone()), ..Default::default() };
                        cfg.ai.base_url = Some(format!("http://{}", provider.local_addr().unwrap()));
                        cfg.ai.api_key = Some(sentinel.into());
                        // config 命令与库启动分别经过同一预检，不依赖数据库或 provider 的拒绝行为。
                        let config_error = cfg.validate().unwrap_err();
                        let startup_error = crate::Daemon::start(cfg).await.err().unwrap();
                        for error in [config_error, startup_error] {
                            for text in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
                                assert!(!text.contains(sentinel) && !text.contains(parameter));
                                tracing::error!(target: "memoswish::config::validation", error = %text, "Configuration rejected");
                            }
                        }
                        if existing {
                            assert_eq!(std::fs::read_to_string(root.join("jwt_secret")).unwrap(), key);
                            assert_eq!(
                                std::fs::read_dir(&root).unwrap().count(),
                                1,
                                "no installation lock or database publication"
                            );
                            std::fs::remove_dir_all(root).unwrap();
                        } else {
                            assert!(!root.exists(), "no installation directory, lock or key publication");
                        }
                    }
                }
            }
            .with_subscriber(subscriber)
            .await;
            let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert!(logs.contains("Configuration rejected"), "capture must observe startup diagnostics");
            assert!(
                !logs.contains(sentinel) && !logs.contains(parameter),
                "credential or parameter name leaked: {logs}"
            );
        }
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), database.accept()).await.is_err());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), provider.accept()).await.is_err());
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn supported_native_database_options_remain_accepted() {
        for url in [
            "sqlite::memory:?mode=memory&cache=private&immutable=false",
            "postgres://user:synthetic@localhost/db?sslmode=disable&application_name=s26b&options=-c%20search_path%3Dpublic",
            "postgresql://user:synthetic@%2Fvar%2Frun%2Fpostgresql/db?ssl-mode=prefer&options[search_path]=public&statement-cache-capacity=20",
            "postgres://user:synthetic@localhost/db?hostaddr=127.0.0.1&port=5432&dbname=db&user=user&password=synthetic&ssl-ca=root.pem&ssl-cert=client.pem&ssl-key=key.pem",
        ] {
            validate_database_options(url).unwrap();
        }
    }
    fn invalid_configs() -> Vec<Config> {
        let cfg = Config::default();
        let mut cases = vec![];
        for value in [0, u64::MAX] {
            let mut c = cfg.clone();
            c.jwt_ttl_secs = value;
            cases.push(c);
            let mut c = cfg.clone();
            c.object_store.put_shutdown_timeout_secs = value;
            cases.push(c);
            let mut c = cfg.clone();
            c.object_store.put_admission_timeout_ms = value;
            cases.push(c);
        }
        let mut c = cfg.clone();
        c.health_bind = c.bind.clone();
        cases.push(c);
        let mut c = cfg.clone();
        c.health_bind = "0.0.0.0:8787".into();
        cases.push(c);
        let mut c = cfg.clone();
        c.feed.max_page = 0;
        cases.push(c);
        let mut c = cfg.clone();
        c.feed.new_weight = -0.1;
        cases.push(c);
        let mut c = cfg.clone();
        c.feed.desired_retention = f64::NAN;
        cases.push(c);
        let mut c = cfg.clone();
        c.object_store.max_concurrent_puts = 0;
        cases.push(c);
        let mut c = cfg.clone();
        c.tts.default_engine = "unknown".into();
        cases.push(c);
        let mut c = cfg.clone();
        c.tts.http = vec![Default::default(), Default::default()];
        cases.push(c);
        let mut c = cfg.clone();
        c.tts.http.push(memoswish_media::tts::http::HttpTtsConfig { timeout_secs: 0, ..Default::default() });
        cases.push(c);
        let mut c = cfg.clone();
        c.ai.base_url = Some("http://user:SECRET@localhost".into());
        cases.push(c);
        for invalid in ["program", "argument", "voice"] {
            let mut c = cfg.clone();
            let mut command: memoswish_media::tts::command::CommandTtsConfig =
                serde_json::from_value(serde_json::json!({"program":"espeak-ng"})).unwrap();
            match invalid {
                "program" => command.program.push('\0'),
                "argument" => command.args.push("--voice=\0".into()),
                _ => command.default_voice.clear(),
            }
            c.tts.commands.push(command);
            cases.push(c);
        }
        for workers in [0, 1, 17] {
            let mut c = cfg.clone();
            c.password_work.workers = workers;
            cases.push(c);
        }
        let mut c = cfg.clone();
        c.password_work.queue = 65;
        cases.push(c);
        for max_bytes in [31, 1025] {
            let mut c = cfg.clone();
            c.password_work.max_bytes = max_bytes;
            cases.push(c);
        }
        let mut c = cfg.clone();
        c.admission.auth_failure = memoswish_core::rate_limit::FailureMode::Open;
        cases.push(c);
        let mut c = cfg.clone();
        c.admission.max_keys = 4095;
        cases.push(c);
        for profile in [crate::PasswordProfile::Enabled, crate::PasswordProfile::Disabled] {
            let mut c = cfg.clone();
            c.password_profile = profile;
            c.mode = memoswish_protocol::DeploymentMode::MultiTenant;
            c.registration_open = true;
            cases.push(c);
        }
        for smtp in [
            crate::SmtpConfig { password: "SECRET".into(), ..Default::default() },
            crate::SmtpConfig { host: "SECRET@invalid".into(), ..Default::default() },
            crate::SmtpConfig { host: "smtp.invalid".into(), port: 0, ..Default::default() },
        ] {
            let mut c = cfg.clone();
            c.smtp = smtp;
            cases.push(c);
        }
        for (peers, header) in [(0, Some("x-real-ip")), (1, None), (1, Some("SECRET")), (33, Some("x-real-ip"))] {
            let mut c = cfg.clone();
            c.proxy_trust.trusted_peers = vec!["127.0.0.1".parse().unwrap(); peers];
            c.proxy_trust.normalized_header = header.map(str::to_owned);
            cases.push(c);
        }
        for endpoint in [
            "S26B_CREDENTIAL_SENTINEL",
            "https://user:S26B_CREDENTIAL_SENTINEL@localhost/api/1/envelope/",
            "https://localhost/api/1/envelope/?token=S26B_CREDENTIAL_SENTINEL",
        ] {
            let mut c = cfg.clone();
            c.diagnostic_forwarding.enabled = true;
            c.diagnostic_forwarding.endpoint = endpoint.into();
            c.diagnostic_forwarding.public_key = "S26B_CREDENTIAL_SENTINEL".into();
            cases.push(c);
        }
        let mut c = cfg;
        c.health_bind = "SECRET".into();
        cases.push(c);
        cases
    }
    #[tokio::test]
    async fn every_invalid_effective_config_precedes_network_and_filesystem_effects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        for mut cfg in invalid_configs() {
            let root = std::env::temp_dir().join(format!("s26b-invalid-{}", memoswish_core::ids::new_id()));
            cfg.data_dir = root.clone();
            // PostgreSQL TCP mock 必须从未观察到连接，甚至还未取得安装锁。
            cfg.database_url = Some(format!("postgres://{}:SECRET@{}/db", "user", listener.local_addr().unwrap()));
            let error = crate::Daemon::start(cfg).await.err().unwrap();
            assert!(!root.exists());
            for text in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
                assert!(!text.contains("SECRET") && !text.contains("S26B_CREDENTIAL_SENTINEL"));
            }
        }
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept()).await.is_err());
    }
    #[tokio::test]
    async fn corrupt_existing_key_precedes_migration_and_provider_contact() {
        let root = std::env::temp_dir().join(format!("s26b-corrupt-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("jwt_secret");
        std::fs::write(&path, b"short").unwrap();
        let config = Config { data_dir: root.clone(), ..Default::default() };
        assert!(crate::Daemon::start(config).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
        assert!(!root.join("learntok.db").exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn credential_types_and_smtp_obey_one_diagnostic_contract() {
        let sentinel = "S26B_CREDENTIAL_SENTINEL";
        let mut config = Config {
            jwt_secret: Some(sentinel.repeat(2)),
            database_url: Some(format!("postgres://user:{sentinel}@localhost/db")),
            ..Default::default()
        };
        config.diagnostic_forwarding.endpoint = format!("https://user:{sentinel}@localhost/api/1/envelope/");
        config.diagnostic_forwarding.public_key = sentinel.into();
        config.diagnostic_forwarding.purpose_version = sentinel.into();
        config.oidc.encryption_key = sentinel.into();
        config.oidc.providers.push(memoswish_auth::oidc_config::OidcProvider {
            client_secret: sentinel.into(),
            apple_private_key: sentinel.into(),
            ..Default::default()
        });
        config.ai.api_key = Some(sentinel.into());
        config.smtp.username = sentinel.into();
        config.smtp.password = sentinel.into();
        config.admission.redis_url = Some(format!("redis://user:{sentinel}@localhost"));
        config.object_store.s3.secret_access_key = sentinel.into();
        config
            .tts
            .http
            .push(memoswish_media::tts::http::HttpTtsConfig { api_key: Some(sentinel.into()), ..Default::default() });
        config.oauth.issuer = format!("https://user:{sentinel}@localhost");
        for text in [
            format!("{config:?}"),
            format!("{:?}", config.oidc.providers),
            format!("{:?}", config.oauth),
            format!("{:?}", config.tts),
            format!("{:?}", config.ai),
            format!("{:?}", config.admission),
            format!("{:?}", config.object_store),
            format!("{:?}", config.smtp),
            toml::to_string(&config.redacted()).unwrap(),
        ] {
            assert!(!text.contains(sentinel));
        }
        // SMTP 已是受支持配置；语法正确但缺 host 时由有效配置校验拒绝。
        let smtp = Config::parse(&format!("[smtp]\npassword='{sentinel}'")).unwrap();
        let error = smtp.validate().unwrap_err();
        for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
            assert!(!output.contains(sentinel));
        }
        for text in [
            format!("[diagnostic_forwarding]\nenabled='{sentinel}'"),
            format!("[smtp]\npassword={{value='{sentinel}'}}"),
            format!("[oidc]\nenabled='{sentinel}'"),
            format!("[password_work]\nworkers='{sentinel}'"),
            format!("[password_work]\n{sentinel}='{sentinel}'"),
            format!("[proxy_trust]\ntrusted_peers=['{sentinel}']"),
            format!("[proxy_trust]\n{sentinel}='{sentinel}'"),
            format!("[proxy_trust]\nnormalized_header={{value='{sentinel}'}}"),
            format!("[admission]\nauth_failure='{sentinel}'"),
        ] {
            let error = Config::parse(&text).unwrap_err();
            for output in [format!("{error}"), format!("{error:#}"), format!("{error:?}")] {
                assert!(!output.contains(sentinel));
            }
        }
    }
}

#[cfg(test)]
mod hf12_tests {
    use super::*;

    #[test]
    fn hf12_pool_configuration_rejects_zero_before_side_effects() {
        assert_eq!(Config::default().db_max_connections, None);
        for database in ["sqlite::memory:", "sqlite://hf12.db", "postgres://localhost/hf12"] {
            let cfg = Config { database_url: Some(database.into()), db_max_connections: Some(0), ..Default::default() };
            assert!(cfg.validate_runtime_values().is_err());
        }
        for maximum in [1, 2, 8, 10] {
            let cfg = Config { db_max_connections: Some(maximum), ..Default::default() };
            cfg.validate_runtime_values().unwrap();
        }
    }
}
