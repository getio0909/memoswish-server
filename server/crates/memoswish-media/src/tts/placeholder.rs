//! 占位 TTS：每个词合成一段音调（音高随词变化），时间戳精确对齐。
//!
//! 它不是真实人声，用途是：零依赖跑通“发音音轨 → 音频闪避 → 卡拉 OK 字幕”的全链路、做 CI 与 UI 调试。

use async_trait::async_trait;
use memoswish_core::tts::{TtsEngine, TtsOutput, TtsRequest, VoiceInfo};
use memoswish_core::{CoreError, CoreResult};
use memoswish_protocol::WordTimestamp;

use crate::segment::tokenize;
use crate::wav::{SAMPLE_RATE, encode_wav, silence, tone};

/// 占位 TTS 引擎。
#[derive(Debug, Default, Clone)]
pub struct PlaceholderTts;

/// 单个词的时长（毫秒）：基础 160ms + 每字符 55ms，上限 900ms。
fn word_ms(chars: u32, speed: f32) -> u32 {
    let base = (160 + 55 * chars).min(900) as f32;
    (base / speed.clamp(0.5, 2.0)) as u32
}

#[async_trait]
impl TtsEngine for PlaceholderTts {
    fn id(&self) -> &str {
        "placeholder"
    }

    fn voices(&self) -> Vec<VoiceInfo> {
        vec![VoiceInfo {
            id: "default".into(),
            language: "*".into(),
            description: "Synthetic beeps (not speech)".into(),
        }]
    }

    async fn diagnostics(&self) -> memoswish_protocol::SpeechDiagnostic {
        memoswish_protocol::SpeechDiagnostic {
            engine: self.id().into(),
            configured: true,
            state: memoswish_protocol::SpeechDiagnosticState::Demo,
            voices: vec!["default".into()],
        }
    }
    async fn synthesize(&self, req: &TtsRequest) -> CoreResult<TtsOutput> {
        self.prepare_execution(req).await?.await
    }

    async fn prepare_execution<'a>(
        &'a self,
        req: &'a TtsRequest,
    ) -> CoreResult<memoswish_core::tts::PreparedSpeech<'a>> {
        req.validate()?;
        let permit = super::EXECUTIONS
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("speech execution capacity exhausted".into()))?;
        let req = req.clone();
        Ok(Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                synthesize_demo(&req)
            })
            .await
            .map_err(|_| CoreError::Unavailable("demo speech worker interrupted".into()))?
        }))
    }
}

fn synthesize_demo(req: &TtsRequest) -> CoreResult<TtsOutput> {
    let tokens = tokenize(&req.text);
    if tokens.is_empty() {
        return Err(CoreError::invalid("nothing to synthesize"));
    }
    if tokens.len() > 400 {
        return Err(CoreError::invalid("text too long for a micro card (max 400 words)"));
    }
    const LEAD_MS: u32 = 80;
    const GAP_MS: u32 = 70;
    const PAUSE_MS: u32 = 220;
    let duration: u32 = LEAD_MS
        + tokens
            .iter()
            .map(|t| word_ms(t.char_end - t.char_start, req.speed) + if t.pause_after { PAUSE_MS } else { GAP_MS })
            .sum::<u32>();
    if duration > 300_000 || (u64::from(duration) * u64::from(SAMPLE_RATE) / 1000) * 2 + 44 > super::AUDIO_BYTES as u64
    {
        return Err(CoreError::invalid("demo speech exceeds PCM envelope"));
    }
    let budget = memoswish_content::processing::WorkBudget::default();
    let mut samples = silence(LEAD_MS, SAMPLE_RATE);
    let mut cursor = LEAD_MS;
    let mut words = Vec::with_capacity(tokens.len());
    for (i, t) in tokens.iter().enumerate() {
        budget.charge(1)?;
        let ms = word_ms(t.char_end - t.char_start, req.speed);
        // 音高在五声音阶上循环，听感更自然。
        let freq = [392.0, 440.0, 523.25, 587.33, 659.25][i % 5];
        samples.extend(tone(freq, ms, 0.35, SAMPLE_RATE));
        words.push(WordTimestamp {
            text: t.text.clone(),
            start_ms: cursor,
            end_ms: cursor + ms,
            char_start: t.char_start,
            char_end: t.char_end,
        });
        let gap = if t.pause_after { PAUSE_MS } else { GAP_MS };
        samples.extend(silence(gap, SAMPLE_RATE));
        cursor += ms + gap;
    }
    let duration_ms = (samples.len() as u64 * 1000 / SAMPLE_RATE as u64) as u32;
    // 浮点取整可能让最后一个词略超总时长，这里钳制以满足协议不变量。
    if let Some(last) = words.last_mut() {
        last.end_ms = last.end_ms.min(duration_ms);
    }
    Ok(TtsOutput {
        alignment_quality: Some(memoswish_protocol::AlignmentQuality::Native),
        audio_kind: Some(memoswish_protocol::AudioKind::Demo),
        provenance: None,
        audio: encode_wav(&samples, SAMPLE_RATE),
        mime: "audio/wav".into(),
        extension: "wav".into(),
        duration_ms,
        words,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wav::wav_duration_ms;

    #[tokio::test]
    async fn timestamps_cover_audio() {
        let out = PlaceholderTts
            .synthesize(&TtsRequest {
                text: "serendipity, finding something good".into(),
                language: "en-US".into(),
                voice: "default".into(),
                speed: 1.0,
            })
            .await
            .unwrap();
        assert_eq!(out.words.len(), 4);
        assert_eq!(wav_duration_ms(&out.audio), Some(out.duration_ms));
        assert!(out.words.windows(2).all(|w| w[0].end_ms <= w[1].start_ms));
        assert!(out.words.last().unwrap().end_ms <= out.duration_ms);
        // 逗号后应有更长停顿。
        assert!(out.words[1].start_ms - out.words[0].end_ms > out.words[2].start_ms - out.words[1].end_ms);
    }
}
