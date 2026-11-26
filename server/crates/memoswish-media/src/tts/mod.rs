//! TTS 引擎实现。
//!
//! | 引擎 | 说明 | 时间戳 |
//! | --- | --- | --- |
//! | `placeholder` | 零依赖，按词合成提示音（非人声），用于开发与 CI | 精确 |
//! | `command` | 调用本地命令（espeak-ng / piper 等）输出 WAV | 按字符权重估算 |
//! | `http` | 调用兼容 OpenAI `/v1/audio/speech` 或带词边界 JSON 的云端 HTTP TTS | 原生词边界或按字符权重估算 |

// 命令、探测和 HTTP 共用有限执行容量；CPU 解码任务持有原许可直到结束。
pub(crate) static EXECUTIONS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

pub const AUDIO_BYTES: usize = 10 * 1024 * 1024;
pub const SPEECH_JSON_BYTES: usize = AUDIO_BYTES.div_ceil(3) * 4 + 1024 * 1024;

pub fn validate_timestamps(text: &str, words: &[WordTimestamp], duration_ms: u32) -> memoswish_core::CoreResult<()> {
    let chars = text.chars().count();
    if text.len() > 8000
        || chars > 2000
        || duration_ms == 0
        || duration_ms > 300_000
        || words.len() > 8000
        || words.iter().any(|word| {
            word.text.len() > 8192
                || word.start_ms > word.end_ms
                || word.end_ms > duration_ms
                || word.char_start > word.char_end
                || word.char_end as usize > chars
        })
        || words.windows(2).any(|pair| pair[0].end_ms > pair[1].start_ms || pair[0].char_end > pair[1].char_start)
        || words.iter().map(|word| word.text.len() + 32).sum::<usize>() > 1024 * 1024
    {
        return Err(memoswish_core::CoreError::invalid("speech timestamps exceed envelope"));
    }
    Ok(())
}

pub mod command;
pub mod disabled;
pub mod http;
pub mod placeholder;

use memoswish_protocol::WordTimestamp;

use crate::segment::{Token, tokenize};

/// 对原始文本分词并按默认首尾静音（60ms / 120ms）估算逐词时间戳。
pub fn estimate_word_timestamps(text: &str, duration_ms: u32) -> Vec<WordTimestamp> {
    let tokens = tokenize(text);
    estimate_timestamps(&tokens, duration_ms, 60, 120)
}

/// 按字符权重把总时长分配给各 token（用于无法返回词边界的引擎）。
///
/// `lead_ms` / `tail_ms` 为首尾静音估计；停顿型标点额外占用 `pause_weight` 个字符权重。
pub fn estimate_timestamps(tokens: &[Token], duration_ms: u32, lead_ms: u32, tail_ms: u32) -> Vec<WordTimestamp> {
    const PAUSE_WEIGHT: f64 = 2.5;
    // 词间留白占每个词时长的比例，保证相邻词时间戳不重叠。
    const GAP_RATIO: f64 = 0.08;
    if tokens.is_empty() {
        return vec![];
    }
    let speech = duration_ms.saturating_sub(lead_ms + tail_ms).max(tokens.len() as u32) as f64;
    let weights: Vec<f64> = tokens
        .iter()
        .map(|t| (t.char_end - t.char_start).max(1) as f64 + if t.pause_after { PAUSE_WEIGHT } else { 0.0 })
        .collect();
    let total: f64 = weights.iter().sum();
    let mut cursor = lead_ms.min(duration_ms) as f64;
    let mut out = Vec::with_capacity(tokens.len());
    for (t, w) in tokens.iter().zip(weights) {
        let span = speech * w / total;
        let pause = if t.pause_after { speech * PAUSE_WEIGHT / total } else { 0.0 };
        let voiced = (span - pause).max(1.0);
        let start = cursor.round() as u32;
        let end = (cursor + voiced * (1.0 - GAP_RATIO)).round().max(start as f64) as u32;
        out.push(WordTimestamp {
            text: t.text.clone(),
            start_ms: start.min(duration_ms),
            end_ms: end.min(duration_ms),
            char_start: t.char_start,
            char_end: t.char_end,
        });
        cursor += span;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::tokenize;

    #[test]
    fn estimates_are_monotonic_and_bounded() {
        let tokens = tokenize("The quick brown fox, jumps over the lazy dog.");
        let ws = estimate_timestamps(&tokens, 3_000, 100, 150);
        assert_eq!(ws.len(), tokens.len());
        let mut prev = 0;
        for w in &ws {
            assert!(w.start_ms >= prev && w.end_ms >= w.start_ms && w.end_ms <= 3_000);
            prev = w.end_ms;
        }
        assert!(ws[0].start_ms >= 100);
        assert!(estimate_timestamps(&[], 1000, 0, 0).is_empty());
    }
}
