//! 未配置语音不阻断内容服务，也不回退提示音。
use async_trait::async_trait;
use memoswish_core::{CoreError, CoreResult, tts::*};

pub struct DisabledTts;
#[async_trait]
impl TtsEngine for DisabledTts {
    fn id(&self) -> &str {
        "unconfigured"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn diagnostics(&self) -> memoswish_protocol::SpeechDiagnostic {
        memoswish_protocol::SpeechDiagnostic {
            engine: self.id().into(),
            configured: false,
            state: memoswish_protocol::SpeechDiagnosticState::Unconfigured,
            voices: vec![],
        }
    }
    async fn synthesize(&self, _: &TtsRequest) -> CoreResult<TtsOutput> {
        Err(CoreError::SpeechUnconfigured)
    }
}
