//! 从暂停 scale 分支吸收的异步准入适配器；整数计量与 governor 共用策略。

use std::time::{Duration, Instant};

use async_trait::async_trait;
use memoswish_core::{
    CoreError, CoreResult,
    ids::sha256_hex,
    rate_limit::{AdmissionQuota, RateLimiter},
};
use redis::{
    Script,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use tokio::sync::RwLock;

const SCRIPT: &str = r#"
local t = redis.call('TIME')
local now = tonumber(t[1])*1000000 + tonumber(t[2])
local cap,period,cost = tonumber(ARGV[1]),tonumber(ARGV[2]),tonumber(ARGV[3])
local old = redis.call('HMGET',KEYS[1],'tokens','time')
local last = tonumber(old[2]) or now
now = math.max(now,last)
local tokens = math.min(cap,(tonumber(old[1]) or cap)+(now-last)*1000/period)
local allowed = 0
if tokens >= cost then tokens = tokens-cost allowed = 1 end
redis.call('HSET',KEYS[1],'tokens',tokens,'time',now)
redis.call('PEXPIRE',KEYS[1],ARGV[4])
return allowed
"#;

pub struct RedisRateLimiter {
    client: redis::Client,
    connection: RwLock<ConnectionState>,
    prefix: String,
    quota: AdmissionQuota,
    timeout: Duration,
}

struct ConnectionState {
    manager: Option<ConnectionManager>,
    generation: u64,
    reconnect_after: Instant,
}

impl RedisRateLimiter {
    /// 启动只验证配置，首次调用有界建连；启动故障也经过相同的路由故障策略。
    pub fn new(url: &str, prefix: String, quota: AdmissionQuota, timeout: Duration) -> CoreResult<Self> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) || prefix.is_empty() || prefix.len() > 128 {
            return Err(CoreError::invalid("invalid Redis limiter configuration"));
        }
        let client = redis::Client::open(url).map_err(|_| CoreError::invalid("invalid Redis URL"))?;
        Ok(Self {
            client,
            connection: RwLock::new(ConnectionState { manager: None, generation: 0, reconnect_after: Instant::now() }),
            prefix,
            quota,
            timeout,
        })
    }

    async fn manager(&self) -> redis::RedisResult<ConnectionManager> {
        ConnectionManager::new_with_config(
            self.client.clone(),
            ConnectionManagerConfig::new()
                .set_connection_timeout(Some(self.timeout))
                .set_response_timeout(Some(self.timeout))
                .set_number_of_retries(1),
        )
        .await
    }

    async fn connection(&self) -> CoreResult<(ConnectionManager, u64)> {
        {
            let state = self.connection.read().await;
            if let Some(manager) = &state.manager {
                return Ok((manager.clone(), state.generation));
            }
        }
        let mut state = self.connection.write().await;
        if state.manager.is_none() {
            if Instant::now() < state.reconnect_after {
                return Err(unavailable());
            }
            state.reconnect_after = Instant::now() + self.timeout;
            state.manager = Some(self.manager().await.map_err(|_| unavailable())?);
            state.reconnect_after = Instant::now();
        }
        Ok((state.manager.as_ref().ok_or_else(unavailable)?.clone(), state.generation))
    }

    async fn invoke(&self, key: &str, cells: u32, mut conn: ConnectionManager) -> redis::RedisResult<i64> {
        // redis-rs 在 NOSCRIPT 时加载脚本并重试；此时原写入尚未发生。
        Script::new(SCRIPT)
            .key(self.key(key))
            .arg(self.quota.burst().get())
            .arg(self.quota.period().as_nanos() as u64)
            .arg(cells)
            .arg(self.quota.ttl().as_millis() as u64)
            .invoke_async(&mut conn)
            .await
    }

    async fn check_redis(&self, key: &str, cells: u32) -> CoreResult<i64> {
        let (manager, generation) = self.connection().await?;
        match self.invoke(key, cells, manager).await {
            // READONLY 拒绝写入后才允许一次替换与重试；丢失响应和超时绝不重放扣费。
            Err(error) if error.kind() == redis::ErrorKind::Server(redis::ServerErrorKind::ReadOnly) => {
                let manager = {
                    let mut state = self.connection.write().await;
                    if state.generation == generation {
                        if Instant::now() < state.reconnect_after {
                            return Err(unavailable());
                        }
                        state.reconnect_after = Instant::now() + self.timeout;
                        state.manager = None;
                        state.generation += 1;
                        state.manager = Some(self.manager().await.map_err(|_| unavailable())?);
                    }
                    state.manager.as_ref().ok_or_else(unavailable)?.clone()
                };
                self.invoke(key, cells, manager).await.map_err(|_| unavailable())
            }
            result => result.map_err(|_| unavailable()),
        }
    }

    fn key(&self, key: &str) -> String {
        format!(
            "{}:rl:v2:{}:{}:{}:{}",
            self.prefix,
            self.quota.scale(),
            self.quota.burst(),
            self.quota.period().as_nanos(),
            sha256_hex(key.as_bytes())
        )
    }
}

fn unavailable() -> CoreError {
    CoreError::Unavailable("rate limiter unavailable".into())
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check(&self, key: &str, cost: f64) -> CoreResult<()> {
        let cells = self.quota.cost_cells(cost)?;
        // 建连、锁等待、脚本和唯一安全重试共用总期限。
        let allowed = tokio::time::timeout(self.timeout, self.check_redis(key, cells.get()))
            .await
            .map_err(|_| unavailable())??;
        match allowed {
            1 => Ok(()),
            0 => Err(CoreError::QuotaExceeded("rate limit exceeded, retry later".into())),
            _ => Err(unavailable()),
        }
    }
}

#[cfg(test)]
#[path = "redis_limiter_tests.rs"]
mod tests;
