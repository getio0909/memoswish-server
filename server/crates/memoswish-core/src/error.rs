//! 统一错误模型。HTTP 层与 MCP 层分别把它映射为 `ApiError` 和 JSON-RPC 错误。

use std::borrow::Cow;
use thiserror::Error;

/// 领域错误。
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0} not found")]
    NotFound(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("use LeaveWorkspace, DeleteWorkspace or CloseAccount")]
    UseExplicitCommand,
    #[error("feed session expired")]
    SessionExpired,
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("speech is unconfigured; configure local eSpeak or explicitly select demo")]
    SpeechUnconfigured,
    #[error("local speech engine is unavailable; check installation and query speech diagnostics")]
    SpeechEngineUnavailable,
    #[error("local speech voice is unavailable; install voice data or choose an available voice")]
    SpeechVoiceUnavailable,
    #[error("temporarily unavailable: {0}")]
    Unavailable(String),
    // 仅在内部重试路径保留有限原因，公共错误映射与普通不可用相同。
    #[error("temporarily unavailable")]
    FeedRetry(crate::observability::FeedRetryCause),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl CoreError {
    /// 公共适配器只发布受控消息，原始 SQL、提供者或输入片段不进入响应和日志。
    pub fn public_message(&self) -> Cow<'static, str> {
        // 仅保留内容 CAS 的数值版本，其他错误上下文仍使用固定公共消息。
        let revision = match self {
            Self::Conflict(message) => [
                "revision mismatch; current revision ",
                "revision exhausted; current revision ",
                "card changed; current revision ",
            ]
            .iter()
            .find_map(|prefix| message.strip_prefix(prefix))
            .and_then(|value| value.parse::<u32>().ok()),
            _ => None,
        };
        if let Some(revision) = revision {
            return format!("resource conflict; current revision {revision}").into();
        }
        (match self {
            Self::NotFound(_) => "resource not found",
            Self::UseExplicitCommand => "Use LeaveWorkspace, DeleteWorkspace or CloseAccount explicitly.",
            Self::SessionExpired => "feed session expired",
            Self::Unauthorized(_) => "authentication required",
            Self::Forbidden(_) => "forbidden",
            Self::Invalid(_) => "invalid input",
            Self::Conflict(_) => "resource conflict",
            Self::QuotaExceeded(_) => "quota exceeded",
            Self::SpeechUnconfigured => {
                "Speech is unconfigured. Configure local eSpeak or explicitly select a demo engine."
            }
            Self::SpeechEngineUnavailable => {
                "Local speech engine is unavailable. Check the installation and query tts_engines diagnostics."
            }
            Self::SpeechVoiceUnavailable => {
                "Local speech voice is unavailable. Install voice data or choose a voice from tts_engines diagnostics."
            }
            Self::Unavailable(_) | Self::FeedRetry(_) => "temporarily unavailable",
            Self::Unsupported(_) => "unsupported operation",
            Self::Internal(_) => "internal server error",
        })
        .into()
    }

    /// 机器可读错误码，用于协议响应。
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::NotFound(_) => "not_found",
            CoreError::UseExplicitCommand => "use_explicit_command",
            CoreError::SessionExpired => "session_expired",
            CoreError::Unauthorized(_) => "unauthorized",
            CoreError::Forbidden(_) => "forbidden",
            CoreError::Invalid(_) => "bad_request",
            CoreError::Conflict(_) => "conflict",
            CoreError::QuotaExceeded(_) => "quota_exceeded",
            CoreError::SpeechUnconfigured => "speech_unconfigured",
            CoreError::SpeechEngineUnavailable => "speech_engine_unavailable",
            CoreError::SpeechVoiceUnavailable => "speech_voice_unavailable",
            CoreError::Unavailable(_) | CoreError::FeedRetry(_) => "temporarily_unavailable",
            CoreError::Unsupported(_) => "unsupported",
            CoreError::Internal(_) => "internal",
        }
    }

    /// 对应的 HTTP 状态码。
    pub fn http_status(&self) -> u16 {
        match self {
            CoreError::NotFound(_) => 404,
            CoreError::SessionExpired => 410,
            CoreError::Unauthorized(_) => 401,
            CoreError::Forbidden(_) => 403,
            CoreError::Invalid(_) => 400,
            CoreError::Conflict(_) | CoreError::UseExplicitCommand => 409,
            CoreError::QuotaExceeded(_) => 429,
            CoreError::SpeechUnconfigured
            | CoreError::SpeechEngineUnavailable
            | CoreError::SpeechVoiceUnavailable
            | CoreError::Unavailable(_)
            | CoreError::FeedRetry(_) => 503,
            CoreError::Unsupported(_) => 501,
            CoreError::Internal(_) => 500,
        }
    }

    /// 便捷构造：内部错误。
    pub fn internal(e: impl std::fmt::Display) -> Self {
        CoreError::Internal(anyhow::anyhow!("{e}"))
    }

    /// 便捷构造：参数错误。
    pub fn invalid(msg: impl Into<String>) -> Self {
        CoreError::Invalid(msg.into())
    }
}

/// 领域结果类型。
pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_messages_never_include_error_payloads() {
        let secret = "S28_SECRET_SENTINEL";
        for error in [
            CoreError::NotFound(secret.into()),
            CoreError::Unauthorized(secret.into()),
            CoreError::Forbidden(secret.into()),
            CoreError::Invalid(secret.into()),
            CoreError::Conflict(secret.into()),
            CoreError::QuotaExceeded(secret.into()),
            CoreError::Unavailable(secret.into()),
            CoreError::Unsupported(secret.into()),
            CoreError::internal(secret),
        ] {
            assert!(!error.public_message().contains(secret));
            assert!(!error.code().contains(secret));
            assert!(!error.public_message().is_empty());
        }
    }

    #[test]
    fn public_revision_conflicts_expose_only_validated_numbers() {
        for reason in ["revision mismatch", "revision exhausted", "card changed"] {
            let error = CoreError::Conflict(format!("{reason}; current revision {}", u32::MAX));
            assert_eq!(error.public_message(), "resource conflict; current revision 4294967295");
            assert_eq!(error.code(), "conflict");
            assert_eq!(error.http_status(), 409);
        }
        for message in [
            "revision mismatch; current revision 4; S28_SECRET_SENTINEL",
            "revision mismatch; current revision S28_SECRET_SENTINEL",
            "S28_SECRET_SENTINEL; current revision 4",
            "revision mismatch; current revision 4294967296",
        ] {
            assert_eq!(CoreError::Conflict(message.into()).public_message(), "resource conflict");
        }
    }
}
