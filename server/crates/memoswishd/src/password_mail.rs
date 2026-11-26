//! lettre 负责 SMTP/TLS；本层只管理有界内存投递及脱敏诊断，不建耐久邮件队列。
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use memoswish_auth::password_lifecycle::PasswordMail;
use memoswish_core::{CoreError, CoreResult, password_lifecycle::ChallengePurpose};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordProfile {
    // 默认保留旧部署登录；迁移由运营方显式选择，不因缺邮件静默禁用。
    #[default]
    Legacy,
    Enabled,
    Disabled,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub max_in_flight: usize,
    pub timeout_secs: u64,
}
impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 465,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            max_in_flight: 4,
            timeout_secs: 15,
        }
    }
}
impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SmtpConfig { [REDACTED] }")
    }
}
impl SmtpConfig {
    pub fn configured(&self) -> bool {
        !self.host.is_empty()
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.configured() {
            anyhow::ensure!(
                self.username.is_empty() && self.password.is_empty() && self.from.is_empty(),
                "SMTP host is required"
            );
            return Ok(());
        }
        anyhow::ensure!(
            self.host.len() <= 253
                && self
                    .host
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "invalid SMTP host"
        );
        anyhow::ensure!(
            self.port != 0 && (1..=32).contains(&self.max_in_flight) && (1..=60).contains(&self.timeout_secs),
            "invalid SMTP delivery budget"
        );
        anyhow::ensure!(
            self.username.is_empty() == self.password.is_empty(),
            "SMTP credentials must be supplied together"
        );
        anyhow::ensure!(
            self.username.len() <= 1024
                && self.password.len() <= 4096
                && self.from.len() <= 254
                && self.from.parse::<Mailbox>().is_ok(),
            "invalid SMTP credentials or sender"
        );
        Ok(())
    }
    pub fn redacted(&self) -> Self {
        Self {
            host: if self.host.is_empty() { String::new() } else { "redacted.invalid".into() },
            username: String::new(),
            password: String::new(),
            from: String::new(),
            ..self.clone()
        }
    }
}

struct DeliveryState {
    closed: bool,
    active: usize,
}
pub struct SmtpMail {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    sender: Mailbox,
    permits: Arc<tokio::sync::Semaphore>,
    state: Arc<Mutex<DeliveryState>>,
    finished: Arc<tokio::sync::Notify>,
    timeout: Duration,
}
struct ActiveMail {
    state: Arc<Mutex<DeliveryState>>,
    finished: Arc<tokio::sync::Notify>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for ActiveMail {
    fn drop(&mut self) {
        self.state.lock().unwrap().active -= 1;
        self.finished.notify_waiters();
    }
}
impl SmtpMail {
    pub fn build(c: &SmtpConfig) -> anyhow::Result<Option<Arc<Self>>> {
        c.validate()?;
        if !c.configured() {
            return Ok(None);
        }
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&c.host)
            .map_err(|_| anyhow::anyhow!("SMTP TLS configuration failed"))?
            .port(c.port)
            .timeout(Some(Duration::from_secs(c.timeout_secs)));
        if !c.username.is_empty() {
            builder = builder.credentials(Credentials::new(c.username.clone(), c.password.clone()));
        }
        Ok(Some(Arc::new(Self {
            transport: builder.build(),
            sender: c.from.parse().map_err(|_| anyhow::anyhow!("invalid SMTP sender"))?,
            permits: Arc::new(tokio::sync::Semaphore::new(c.max_in_flight)),
            state: Arc::new(Mutex::new(DeliveryState { closed: false, active: 0 })),
            finished: Arc::new(tokio::sync::Notify::new()),
            timeout: Duration::from_secs(c.timeout_secs),
        })))
    }
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.permits.close();
    }
    pub async fn wait(&self) {
        loop {
            let finished = self.finished.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();
            if self.state.lock().unwrap().active == 0 {
                break;
            }
            finished.await;
        }
    }
}
impl PasswordMail for SmtpMail {
    fn deliver(&self, destination: &str, purpose: ChallengePurpose, token: String) -> CoreResult<()> {
        let unavailable = || CoreError::Unavailable("password mail delivery unavailable".into());
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| unavailable())?;
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(unavailable());
            }
            state.active += 1;
        }
        let active = ActiveMail { state: self.state.clone(), finished: self.finished.clone(), _permit: permit };
        let recipient = destination.parse::<Mailbox>().map_err(|_| unavailable())?;
        let product = env!("BRAND_EN_PRODUCT");
        let subject = match purpose {
            ChallengePurpose::Verify => format!("{product} email verification"),
            ChallengePurpose::Reset => format!("{product} password reset"),
        };
        let message=Message::builder().from(self.sender.clone()).to(recipient).subject(&subject)
            .body(format!("{subject}\n\nEnter this one-time code in {product}:\n{token}\n\nExpires in 30 minutes. A resend replaces the previous code. If you did not request this, ignore this message."))
            .map_err(|_|unavailable())?;
        let transport = self.transport.clone();
        let timeout = self.timeout;
        // 任务拥有许可和正文直至结束；调用方取消不会释放在途容量。
        tokio::spawn(async move {
            let _active = active;
            match tokio::time::timeout(timeout, transport.send(message)).await {
                Ok(Ok(_)) => {}
                _ => {
                    tracing::warn!(target: "memoswish::password_mail", "Password SMTP delivery failed; explicit resend required")
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    pub(super) fn fixture(port: u16) -> SmtpMail {
        SmtpMail {
            transport: AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1").port(port).build(),
            sender: "sender@test.invalid".parse().unwrap(),
            permits: Arc::new(tokio::sync::Semaphore::new(1)),
            state: Arc::new(Mutex::new(DeliveryState { closed: false, active: 0 })),
            finished: Arc::new(tokio::sync::Notify::new()),
            timeout: Duration::from_secs(1),
        }
    }
    #[tokio::test]
    async fn smtp_disconnect_and_ambiguous_acceptance_are_bounded_and_redacted() {
        for after_data in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mail = fixture(listener.local_addr().unwrap().port());
            let (arrived, accepted) = tokio::sync::oneshot::channel();
            let (release, hold) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                stream.get_mut().write_all(b"220 fixture\r\n").await.unwrap();
                let mut transcript = String::new();
                let mut data = false;
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    transcript.push_str(&line);
                    if line.starts_with("EHLO") {
                        stream.get_mut().write_all(b"250 fixture\r\n").await.unwrap();
                    } else if line.starts_with("MAIL") {
                        if !after_data {
                            break;
                        }
                        stream.get_mut().write_all(b"250 ok\r\n").await.unwrap();
                    } else if line.starts_with("RCPT") {
                        stream.get_mut().write_all(b"250 ok\r\n").await.unwrap();
                    } else if line.starts_with("DATA") {
                        stream.get_mut().write_all(b"354 send\r\n").await.unwrap();
                        data = true;
                    } else if data && line == ".\r\n" {
                        let _ = arrived.send(());
                        let _ = hold.await;
                        break;
                    }
                }
                transcript
            });
            mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "synthetic-private-mail-token".into())
                .unwrap();
            if after_data {
                accepted.await.unwrap();
                let error =
                    mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "second-secret".into()).unwrap_err();
                for output in [format!("{error}"), format!("{error:?}")] {
                    assert!(!output.contains("secret"));
                }
                release.send(()).unwrap();
            }
            mail.close();
            mail.wait().await;
            let transcript = server.await.unwrap();
            assert_eq!(transcript.contains("synthetic-private-mail-token"), after_data);
            assert!(mail.deliver("receiver@test.invalid", ChallengePurpose::Verify, "secret".into()).is_err());
            assert_eq!(mail.state.lock().unwrap().active, 0);
        }
    }
    #[tokio::test]
    async fn smtp_requires_tls_and_never_sends_plaintext_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = SmtpConfig {
            host: "localhost".into(),
            port: listener.local_addr().unwrap().port(),
            from: "sender@test.invalid".into(),
            username: "synthetic-private-smtp-user".into(),
            password: "synthetic-private-smtp-password".into(),
            ..Default::default()
        };
        let mail = SmtpMail::build(&config).unwrap().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes[..n]).contains("synthetic-private"));
        });
        mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "synthetic-private-token".into()).unwrap();
        mail.close();
        mail.wait().await;
        server.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn smtp_timeout_retains_capacity_until_worker_finishes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mail = fixture(listener.local_addr().unwrap().port());
        mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "sentinel".into()).unwrap();
        let (_connection, _) = listener.accept().await.unwrap();
        assert!(mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "second".into()).is_err());
        tokio::time::advance(Duration::from_secs(2)).await;
        mail.wait().await;
        assert_eq!(mail.state.lock().unwrap().active, 0);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn daemon_drain_uses_original_deadline_for_inflight_smtp_and_diagnostics() {
        let directory = std::env::temp_dir().join(format!("smtp-drain-{}", memoswish_core::ids::new_id()));
        let mut st = crate::app::AppState::assemble(crate::Config {
            data_dir: directory.clone(),
            seed_demo: false,
            object_store: crate::ObjectStoreConfig { put_shutdown_timeout_secs: 1, ..Default::default() },
            ..Default::default()
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut mail = fixture(listener.local_addr().unwrap().port());
        mail.timeout = Duration::from_secs(60);
        let mail = Arc::new(mail);
        st.password_mail = Some(mail.clone());
        mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "sentinel".into()).unwrap();
        let (connection, _) = listener.accept().await.unwrap();
        Arc::make_mut(&mut st.config).diagnostic_forwarding.enabled = true;
        let (held, dropped) = tokio::sync::oneshot::channel::<()>();
        let forwarding = crate::diagnostics::spawn_forwarding(&st, async move {
            let _held = held;
            std::future::pending::<()>().await;
        })
        .unwrap();
        // SQLx 初始化依赖真实 IO，只有排空阶段使用受控时间。
        tokio::time::pause();
        let deadline = st.health.lifecycle.drain();
        // HTTP 阶段已耗尽同一预算，SMTP 不能另起一个投递超时窗口。
        tokio::time::advance(Duration::from_secs(2)).await;
        crate::runtime::drain_background(&st).await;
        forwarding.await.unwrap();
        assert!(dropped.await.is_err(), "shared deadline must cancel pending diagnostics");
        assert_eq!(st.health.lifecycle.drain(), deadline);
        assert_eq!(st.health.lifecycle.phase(), crate::lifecycle::Phase::Stopped);
        assert!(
            crate::diagnostics::spawn_forwarding(&st, async { panic!("forwarding admitted after drain") }).is_none()
        );
        assert_eq!(mail.state.lock().unwrap().active, 1);
        assert!(mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "second".into()).is_err());
        tokio::time::resume();
        let error = st
            .services
            .auth
            .login(&memoswish_protocol::LoginRequest {
                email: "missing@test.invalid".into(),
                password: "password123".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.http_status(), 503);
        drop(connection);
        mail.wait().await;
        assert_eq!(mail.state.lock().unwrap().active, 0);
        crate::runtime::cleanup_test_app(directory, &[&st]).await;
    }
}

#[cfg(test)]
mod authentication_failure_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    #[tokio::test]
    async fn smtp_auth_rejection_discards_provider_secret_diagnostics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut mail = super::tests::fixture(listener.local_addr().unwrap().port());
        mail.transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(listener.local_addr().unwrap().port())
            .credentials(Credentials::new("synthetic-smtp-user".into(), "synthetic-smtp-password".into()))
            .build();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            stream.get_mut().write_all(b"220 fixture\r\n").await.unwrap();
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("EHLO"));
            stream.get_mut().write_all(b"250-fixture\r\n250 AUTH PLAIN LOGIN\r\n").await.unwrap();
            line.clear();
            stream.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("AUTH"));
            stream.get_mut().write_all(b"535 synthetic-private-provider-secret\r\n").await.unwrap();
        });
        mail.deliver("receiver@test.invalid", ChallengePurpose::Reset, "synthetic-token".into()).unwrap();
        mail.close();
        mail.wait().await;
        server.await.unwrap();
        assert_eq!(mail.state.lock().unwrap().active, 0);
    }
}
