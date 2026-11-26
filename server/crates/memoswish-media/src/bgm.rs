//! BGM 匹配打分与无版权合成 Pad。

use memoswish_protocol::BgmTrack;

use crate::wav::{SAMPLE_RATE, encode_wav};

/// 计算曲目与需求的匹配分（0~1，越高越匹配）。
///
/// 权重：情绪标签交集 0.6、能量接近度 0.25、BPM 接近度 0.15。缺省维度视为满分。
pub fn score(track: &BgmTrack, moods: &[String], energy: Option<f32>, bpm: Option<u16>) -> f32 {
    let mood_score = if moods.is_empty() {
        1.0
    } else {
        let hit = moods.iter().filter(|m| track.moods.iter().any(|t| t.eq_ignore_ascii_case(m))).count();
        hit as f32 / moods.len() as f32
    };
    let energy_score = energy.map_or(1.0, |e| 1.0 - (track.energy - e.clamp(0.0, 1.0)).abs());
    let bpm_score = bpm.map_or(1.0, |b| {
        let diff = (track.bpm as f32 - b as f32).abs();
        (1.0 - diff / 60.0).max(0.0)
    });
    0.6 * mood_score + 0.25 * energy_score + 0.15 * bpm_score
}

/// 内置情绪预设：`(id, title, moods, energy, bpm, 和弦频率)`。
pub type Preset = (&'static str, &'static str, &'static [&'static str], f32, u16, &'static [f32]);

/// 内置预设列表。
pub const PRESETS: &[Preset] = &[
    ("bgm_calm_pad", "Calm Pad", &["calm", "relax"], 0.2, 70, &[130.81, 164.81, 196.0, 246.94]),
    ("bgm_focus_pad", "Focus Pad", &["focus", "calm"], 0.35, 90, &[110.0, 130.81, 164.81, 220.0]),
    ("bgm_upbeat_pulse", "Upbeat Pulse", &["upbeat", "happy"], 0.7, 120, &[146.83, 185.0, 220.0, 293.66]),
    ("bgm_epic_drone", "Epic Drone", &["epic", "intense"], 0.85, 100, &[98.0, 146.83, 196.0, 233.08]),
];

/// 合成可无缝循环的 Pad：频率量化到 `1/seconds` 的整数倍，节拍数取整，首尾样本连续。
pub fn synth_pad(chord: &[f32], bpm: u16, energy: f32, seconds: u32) -> Vec<u8> {
    let sr = SAMPLE_RATE as f32;
    let n = (SAMPLE_RATE * seconds) as usize;
    let quant = |f: f32| (f * seconds as f32).round() / seconds as f32;
    let freqs: Vec<f32> = chord.iter().map(|f| quant(*f)).collect();
    // 每个循环包含整数个节拍，保证脉冲包络在循环点处连续。
    let beats = ((bpm as f32 / 60.0) * seconds as f32).round().max(1.0);
    let beat_hz = beats / seconds as f32;
    let lfo_hz = 1.0 / seconds as f32 * 2.0;
    let pulse_depth = (energy * 0.6).clamp(0.0, 0.6);
    let amp = 0.18 / freqs.len().max(1) as f32 * 2.0;
    let samples: Vec<f32> = (0..n)
        .map(|i| {
            let t = i as f32 / sr;
            let tau = std::f32::consts::TAU;
            let tone: f32 = freqs
                .iter()
                .enumerate()
                .map(|(k, f)| (tau * f * t + k as f32).sin() + 0.3 * (tau * f * 2.0 * t).sin())
                .sum();
            let lfo = 0.75 + 0.25 * (tau * lfo_hz * t).sin();
            let beat_phase = (t * beat_hz).fract();
            let pulse = 1.0 - pulse_depth * beat_phase;
            tone * amp * lfo * pulse
        })
        .collect();
    encode_wav(&samples, SAMPLE_RATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_protocol::examples::sample_bgm_track;

    #[test]
    fn scoring_prefers_matching_mood() {
        let t = sample_bgm_track();
        let focus = score(&t, &["focus".into()], Some(0.3), Some(90));
        let epic = score(&t, &["epic".into()], Some(0.9), Some(140));
        assert!(focus > 0.95);
        assert!(epic < focus);
        assert!((score(&t, &[], None, None) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn pad_has_expected_length() {
        let wav = synth_pad(PRESETS[0].5, 70, 0.2, 2);
        assert_eq!(crate::wav::wav_duration_ms(&wav), Some(2000));
    }
}
