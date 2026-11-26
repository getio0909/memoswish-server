//! 无感行为信号解释：把一次卡片曝光的微交互翻译成 FSRS 评分与标星。

use memoswish_protocol::{ImplicitFeedback, SwipeDirection};
use serde::{Deserialize, Serialize};

use crate::fsrs::Rating;

/// 解释结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// `None` 表示该次曝光不更新记忆模型（例如挂机）。
    pub rating: Option<Rating>,
    /// 是否加入重点记忆库。
    pub star: bool,
}

/// 可调阈值。默认值用于隐式反馈评分。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalPolicy {
    /// 快划阈值：低于此停留时长且上滑、未翻转 → Easy。
    pub fast_swipe_ms: u32,
    /// 循环次数达到此值 → Hard + 标星。
    pub reinforce_loops: u32,
    /// 翻转且停留超过此值 → Hard。
    pub slow_flip_ms: u32,
    /// 停留超过此值视为挂机，忽略。
    pub idle_ms: u32,
}

impl Default for SignalPolicy {
    fn default() -> Self {
        Self { fast_swipe_ms: 1_500, reinforce_loops: 2, slow_flip_ms: 8_000, idle_ms: 120_000 }
    }
}

impl SignalPolicy {
    /// 阈值按实际解释顺序排列，避免全部事件被误分类。
    pub fn validate(&self) -> memoswish_core::CoreResult<()> {
        if self.fast_swipe_ms == 0
            || self.fast_swipe_ms >= self.slow_flip_ms
            || self.slow_flip_ms >= self.idle_ms
            || self.reinforce_loops == 0
        {
            return Err(memoswish_core::CoreError::invalid("invalid feed signal thresholds"));
        }
        Ok(())
    }

    /// 解释单条埋点。规则按优先级依次匹配。
    pub fn interpret(&self, e: &ImplicitFeedback) -> Outcome {
        let loops = if e.muted { 0 } else { e.loop_count };
        let star = e.double_tapped || loops >= self.reinforce_loops;
        let needed_effort = loops >= self.reinforce_loops || (e.flipped && e.dwell_time_ms >= self.slow_flip_ms);
        let rating = if e.dwell_time_ms > self.idle_ms {
            None
        } else if e.long_pressed {
            Some(Rating::Again)
        } else if needed_effort {
            // 多次循环收听，或翻面后长时间停留：记得费力。
            Some(Rating::Hard)
        } else if e.dwell_time_ms < self.fast_swipe_ms && e.swipe_direction == SwipeDirection::Next && !e.flipped {
            Some(Rating::Easy)
        } else {
            Some(Rating::Good)
        };
        Outcome { rating, star }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_protocol::examples::sample_feedback_batch;

    fn ev() -> ImplicitFeedback {
        let mut e = sample_feedback_batch().events[0].clone();
        e.dwell_time_ms = 4_000;
        e.loop_count = 1;
        e.flipped = false;
        e.double_tapped = false;
        e.long_pressed = false;
        e.muted = false;
        e.swipe_direction = SwipeDirection::Next;
        e
    }

    #[test]
    fn rules() {
        let p = SignalPolicy::default();
        assert_eq!(p.interpret(&ev()), Outcome { rating: Some(Rating::Good), star: false });

        let mut fast = ev();
        fast.dwell_time_ms = 900;
        assert_eq!(p.interpret(&fast).rating, Some(Rating::Easy));
        fast.swipe_direction = SwipeDirection::Previous;
        assert_eq!(p.interpret(&fast).rating, Some(Rating::Good));

        let mut looped = ev();
        looped.loop_count = 2;
        assert_eq!(p.interpret(&looped), Outcome { rating: Some(Rating::Hard), star: true });
        looped.muted = true;
        assert_eq!(p.interpret(&looped), Outcome { rating: Some(Rating::Good), star: false });

        let mut help = ev();
        help.long_pressed = true;
        assert_eq!(p.interpret(&help).rating, Some(Rating::Again));

        let mut liked = ev();
        liked.double_tapped = true;
        assert_eq!(p.interpret(&liked), Outcome { rating: Some(Rating::Good), star: true });

        let mut idle = ev();
        idle.dwell_time_ms = 200_000;
        assert_eq!(p.interpret(&idle).rating, None);

        let mut slow_flip = ev();
        slow_flip.flipped = true;
        slow_flip.dwell_time_ms = 9_000;
        assert_eq!(p.interpret(&slow_flip).rating, Some(Rating::Hard));
    }
}
