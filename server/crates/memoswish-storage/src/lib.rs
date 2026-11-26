//! Memoswish 存储后端。
//!
//! - `sqlite`（默认）：单机自托管零依赖。
//! - `postgres`（默认编译）：自托管可选、商业 SaaS 必选。
//! - `local_disk`：本地磁盘对象存储（始终可用）。
//! - `s3`：S3 兼容对象存储（AWS Signature V4 + 预签名 URL）。
//!
//! 运行时通过数据库 URL 的 scheme 选择实现，见 [`connect`]。

#[macro_use]
mod oauth;
#[macro_use]
mod identity;
mod account_export;
#[cfg(test)]
mod asset_conformance;
mod assets;
#[cfg(test)]
mod bgm_conformance;
mod content_lifecycle;
#[cfg(test)]
mod content_lifecycle_conformance;
#[cfg(any(test, feature = "test-support"))]
#[macro_use]
mod candidate_test_support;
#[macro_use]
mod feed_candidates;
mod access;
mod feed_issuance;
#[cfg(test)]
mod feed_issuance_conformance;
#[cfg(test)]
mod import_conformance;
mod imports;
mod learning;
mod learning_controls;
mod lifecycle;
#[cfg(test)]
mod lifecycle_conformance;
pub mod local_disk;
mod membership;
mod migrations;
pub mod ownership;
mod recovery;
#[cfg(feature = "redis")]
pub mod redis_limiter;
pub mod restore_suppression;
pub mod retention;
#[cfg(test)]
mod retention_conformance;
mod s3_config;
#[cfg(test)]
mod session_conformance;
mod sessions;
pub use s3_config::S3Config;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(test)]
mod candidate_conformance;
#[cfg(test)]
mod conformance;
#[cfg(test)]
mod content_conformance;
#[cfg(test)]
mod foundation_conformance;
#[cfg(test)]
mod identity_conformance;
#[cfg(test)]
mod oauth_conformance;
#[cfg(all(any(test, feature = "test-support"), feature = "postgres"))]
pub mod pg_test_support;

use std::sync::Arc;

use memoswish_core::repo::Repository;
use memoswish_core::{CoreError, CoreResult};

pub use local_disk::LocalDiskStore;
#[cfg(feature = "s3")]
pub use s3::S3Store;

/// 数据库后端类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    Sqlite,
    Postgres,
}

impl DatabaseKind {
    /// 根据 URL scheme 判断后端。
    pub fn from_url(url: &str) -> CoreResult<Self> {
        if url.starts_with("sqlite:") {
            Ok(DatabaseKind::Sqlite)
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Ok(DatabaseKind::Postgres)
        } else {
            Err(CoreError::invalid(format!(
                "unsupported database url scheme (expected sqlite: or postgres://): {}",
                redact_url(url)
            )))
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseKind::Sqlite => "sqlite",
            DatabaseKind::Postgres => "postgres",
        }
    }
}

/// 连接数据库、执行迁移并返回聚合仓储。
pub async fn connect(url: &str, max_connections: u32) -> CoreResult<Arc<dyn Repository>> {
    match DatabaseKind::from_url(url)? {
        DatabaseKind::Sqlite => {
            #[cfg(feature = "sqlite")]
            {
                Ok(Arc::new(sqlite::SqliteRepository::connect_with_max_connections(url, max_connections).await?))
            }
            #[cfg(not(feature = "sqlite"))]
            {
                Err(CoreError::Unsupported("this build was compiled without the `sqlite` feature".into()))
            }
        }
        DatabaseKind::Postgres => {
            #[cfg(feature = "postgres")]
            {
                Ok(Arc::new(postgres::PostgresRepository::connect(url, max_connections).await?))
            }
            #[cfg(not(feature = "postgres"))]
            {
                let _ = max_connections;
                Err(CoreError::Unsupported("this build was compiled without the `postgres` feature".into()))
            }
        }
    }
}

/// 只打开已准备的安装；运行角色无隐式 schema 修复能力。
pub async fn open_runtime(url: &str, max_connections: u32) -> CoreResult<Arc<dyn Repository>> {
    match DatabaseKind::from_url(url)? {
        #[cfg(feature = "sqlite")]
        DatabaseKind::Sqlite => {
            Ok(Arc::new(sqlite::SqliteRepository::open_runtime_with_max_connections(url, max_connections).await?))
        }
        #[cfg(feature = "postgres")]
        DatabaseKind::Postgres => Ok(Arc::new(postgres::PostgresRepository::open_runtime(url, max_connections).await?)),
        #[allow(unreachable_patterns)]
        _ => {
            let _ = max_connections;
            Err(CoreError::Unsupported("database backend is unavailable".into()))
        }
    }
}

/// 隐藏 URL 中的密码，用于日志与错误信息。
pub fn redact_url(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(s), Some(at)) if at > s + 3 => {
            let creds = &url[s + 3..at];
            match creds.find(':') {
                Some(c) => format!("{}{}:***{}", &url[..s + 3], &creds[..c], &url[at..]),
                None => url.to_string(),
            }
        }
        _ => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_dispatch_and_redaction() {
        assert_eq!(DatabaseKind::from_url("sqlite://data/a.db").unwrap(), DatabaseKind::Sqlite);
        assert_eq!(DatabaseKind::from_url("sqlite::memory:").unwrap(), DatabaseKind::Sqlite);
        assert_eq!(DatabaseKind::from_url("postgres://u:p@h/db").unwrap(), DatabaseKind::Postgres);
        assert!(DatabaseKind::from_url("mysql://x").is_err());
        assert_eq!(redact_url("postgres://u:secret@h:5432/db"), "postgres://u:***@h:5432/db");
        assert_eq!(redact_url("sqlite://data/a.db"), "sqlite://data/a.db");
    }
}

#[cfg(test)]
mod learning_conformance;

#[cfg(test)]
mod membership_conformance;

#[cfg(test)]
mod compatibility_conformance;
mod erasure;
#[cfg(test)]
mod erasure_conformance;

mod privacy;
#[cfg(test)]
mod privacy_conformance;

/// 显式部署 bootstrap 持有直连 session 锁，连接关闭时由 PostgreSQL 释放。
#[cfg(feature = "postgres")]
pub async fn lock_bootstrap(url: &str) -> CoreResult<sqlx::PgConnection> {
    use sqlx::Connection;
    let mut connection = sqlx::PgConnection::connect(url).await.map_err(|error| {
        let state = error
            .as_database_error()
            .and_then(|e| e.code())
            .filter(|c| c.len() == 5 && c.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
            .map(|c| c.into_owned())
            .unwrap_or_else(|| "transport".into());
        CoreError::Unavailable(format!("bootstrap database connection failed ({state})"))
    })?;
    sqlx::query("SELECT pg_advisory_lock(20871913462601)")
        .execute(&mut connection)
        .await
        .map_err(|_| CoreError::Unavailable("bootstrap coordination failed".into()))?;
    Ok(connection)
}

#[cfg(test)]
mod explanation_conformance;
mod explanations;
mod password_lifecycle;

mod diagnostics;
#[cfg(test)]
mod diagnostics_conformance;
pub mod maintenance;
#[cfg(test)]
mod maintenance_conformance;
#[cfg(test)]
mod password_conformance;

mod operational_metrics;

/// 组装点注入实例观察器，保持迁移与只读运行入口的边界。
pub async fn connect_observed(
    url: &str,
    max: u32,
    migrate: bool,
    observer: Arc<dyn memoswish_core::observability::Observer>,
) -> CoreResult<Arc<dyn Repository>> {
    match DatabaseKind::from_url(url)? {
        #[cfg(feature = "sqlite")]
        DatabaseKind::Sqlite => {
            let repo = if migrate {
                sqlite::SqliteRepository::connect_with_max_connections(url, max).await?
            } else {
                sqlite::SqliteRepository::open_runtime_with_max_connections(url, max).await?
            };
            Ok(Arc::new(repo.with_observer(observer)))
        }
        #[cfg(feature = "postgres")]
        DatabaseKind::Postgres => {
            let repo = if migrate {
                postgres::PostgresRepository::connect(url, max).await?
            } else {
                postgres::PostgresRepository::open_runtime(url, max).await?
            };
            Ok(Arc::new(repo.with_observer(observer)))
        }
        #[allow(unreachable_patterns)]
        _ => {
            let _ = (max, migrate, observer);
            Err(CoreError::Unsupported("database backend is unavailable".into()))
        }
    }
}

#[cfg(test)]
mod operational_conformance;

#[cfg(test)]
mod access_conformance;
#[cfg(test)]
mod learning_controls_conformance;
mod library;
#[cfg(test)]
mod library_conformance;

#[cfg(all(test, any(feature = "sqlite", feature = "postgres", feature = "redis")))]
mod test_environment {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/test-environment.rs"));
}
