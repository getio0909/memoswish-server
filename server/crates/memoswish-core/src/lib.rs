//! Memoswish 领域核心：错误模型、身份与 RBAC、存储 / 对象存储 / TTS 抽象 Trait。
//!
//! 依赖方向：`protocol <- core <- {storage, auth, content, media, feed} <- mcp <- memoswishd`。
//! 本 crate 不依赖任何具体数据库、HTTP 框架或 TTS 实现。

#![warn(clippy::disallowed_methods)]

pub mod asset_read;
pub mod assets;
pub mod bgm;
pub mod content;
pub mod content_lifecycle;
pub mod content_lifecycle_repo;
pub mod content_validation;
pub mod error;
pub mod explanations;
pub mod identity;
pub mod ids;
pub mod imports;
pub mod jobs;
pub mod lifecycle;
pub mod oauth;
pub mod principal;
pub mod rate_limit;
pub mod repo;
pub mod store;
pub mod tts;

pub use error::{CoreError, CoreResult};
pub use principal::{AccountPrincipal, CredentialGenerations, Permission, Principal, Role};

pub mod session;

pub mod erasure;

pub mod privacy;

pub mod diagnostics;
pub mod maintenance;
pub mod password_lifecycle;

pub mod learning_controls;
pub mod library;
pub mod observability;
