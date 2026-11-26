//! FSRS 记忆模型适配层。
//!
//! 算法本身来自上游官方实现 [`fsrs`](https://github.com/open-spaced-repetition/fsrs-rs)（FSRS-6），
//! 这里只做类型转换、天数换算与参数管理；不要在本文件中重新实现公式。
//! 上游 crate 还提供参数优化器（`fsrs::compute_parameters`），路线图 v0.5 将基于用户历史调参。

use memoswish_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

/// 与锁定依赖同步；升级时由回归检查阻止错误的审计版本标签。
pub(crate) const PACKAGE_VERSION: &str = "6.6.2";

// 上游裁剪与参数读取接口均为私有，从下列固定版本抽取构造器的边界表。
// 来源 https://github.com/open-spaced-repetition/fsrs-rs/blob/v6.6.2/src/parameter_clipper.rs
// 适配仅展开常量，固定构造器的 num_relearning_steps=1、enable_short_term=false。
// 升级包时须重新核对，回归通过上游派生 Debug 比较所有实际参数。
// 以下保留上游版权与许可原文。
/*
BSD 3-Clause License

Copyright (c) 2023, Open Spaced Repetition

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
const CONSTRUCTOR_PARAMETER_BOUNDS: [(f32, f32); 21] = [
    (0.001, 100.0),
    (0.001, 100.0),
    (0.001, 100.0),
    (0.001, 100.0),
    (1.0, 10.0),
    (0.001, 4.0),
    (0.001, 4.0),
    (0.001, 0.75),
    (0.0, 4.5),
    (0.0, 0.8),
    (0.001, 3.5),
    (0.001, 5.0),
    (0.001, 0.25),
    (0.001, 0.9),
    (0.0, 4.0),
    (0.0, 1.0),
    (1.0, 6.0),
    (0.0, 2.0),
    (0.0, 2.0),
    (0.0, 0.8),
    (0.1, 0.8),
];

/// FSRS 评分。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Rating {
    Again = 1,
    Hard = 2,
    Good = 3,
    Easy = 4,
}

impl Rating {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Rating::Again),
            2 => Some(Rating::Hard),
            3 => Some(Rating::Good),
            4 => Some(Rating::Easy),
            _ => None,
        }
    }
}

/// 记忆状态（稳定性 S 天、难度 D 1~10）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Memory {
    pub stability: f64,
    pub difficulty: f64,
}

/// 一次评分后的结果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Review {
    pub memory: Memory,
    /// 达到期望保持率的下次间隔（天，可为小数）。
    pub interval_days: f64,
}

/// FSRS 调度器。
#[derive(Debug, Clone)]
pub struct Fsrs {
    inner: fsrs::FSRS,
    parameters: Vec<f32>,
    /// 遗忘曲线衰减参数（参数向量第 21 项）。
    decay: f32,
    /// 期望记忆保持率，默认 0.9。
    pub desired_retention: f64,
}

impl Default for Fsrs {
    fn default() -> Self {
        Self::new(&[], 0.9).expect("default FSRS parameters are valid")
    }
}

impl Fsrs {
    /// 以自定义参数创建（空切片表示上游默认参数）。
    pub fn new(parameters: &[f32], desired_retention: f64) -> CoreResult<Self> {
        let mut filled = fsrs::check_and_fill_parameters(parameters)
            .map_err(|e| CoreError::invalid(format!("invalid FSRS parameters: {e:?}")))?;
        for (parameter, (low, high)) in filled.iter_mut().zip(CONSTRUCTOR_PARAMETER_BOUNDS) {
            *parameter = parameter.clamp(low, high);
        }
        let decay = *filled.last().ok_or_else(|| CoreError::invalid("empty FSRS parameters"))?;
        let inner =
            fsrs::FSRS::new(&filled).map_err(|e| CoreError::invalid(format!("invalid FSRS parameters: {e:?}")))?;
        if !(0.5..=0.99).contains(&desired_retention) {
            return Err(CoreError::invalid("desired_retention must be within [0.5, 0.99]"));
        }
        Ok(Self { inner, parameters: filled, decay, desired_retention })
    }

    /// 上游补全并按构造器边界裁剪后的实际模型参数，包括空配置解析得到的默认值。
    pub fn parameters(&self) -> &[f32] {
        &self.parameters
    }

    /// 可提取率 R(t, S)。
    pub fn retrievability(&self, elapsed_days: f64, stability: f64) -> f64 {
        if stability <= 0.0 {
            return 0.0;
        }
        let state = fsrs::MemoryState { stability: stability as f32, difficulty: 5.0 };
        fsrs::current_retrievability(state, elapsed_days.max(0.0) as f32, self.decay) as f64
    }

    /// 评分后的新记忆状态。`previous = None` 表示首次学习；`elapsed_days` 为距上次复习的天数。
    pub fn review(&self, previous: Option<Memory>, elapsed_days: f64, rating: Rating) -> CoreResult<Review> {
        let prev =
            previous.map(|m| fsrs::MemoryState { stability: m.stability as f32, difficulty: m.difficulty as f32 });
        // 上游以整天计；同日复习（0 天）走 FSRS-6 的短期记忆公式。
        let days = elapsed_days.max(0.0).floor().min(u32::MAX as f64) as u32;
        let next = self
            .inner
            .next_states(prev, self.desired_retention as f32, days)
            .map_err(|e| CoreError::internal(format!("fsrs scheduling failed: {e:?}")))?;
        let state = match rating {
            Rating::Again => next.again,
            Rating::Hard => next.hard,
            Rating::Good => next.good,
            Rating::Easy => next.easy,
        };
        Ok(Review {
            memory: Memory { stability: state.memory.stability as f64, difficulty: state.memory.difficulty as f64 },
            interval_days: state.interval as f64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratings_order_stability() {
        let f = Fsrs::default();
        let first = f.review(None, 0.0, Rating::Good).unwrap().memory;
        let r = |rt| f.review(Some(first), 3.0, rt).unwrap();
        let (again, hard, good, easy) = (r(Rating::Again), r(Rating::Hard), r(Rating::Good), r(Rating::Easy));
        assert!(again.memory.stability < hard.memory.stability);
        assert!(hard.memory.stability < good.memory.stability);
        assert!(good.memory.stability < easy.memory.stability);
        assert!(again.memory.difficulty > easy.memory.difficulty);
        assert!(good.interval_days > 0.0);
    }

    #[test]
    fn retrievability_decays() {
        let f = Fsrs::default();
        assert!((f.retrievability(0.0, 10.0) - 1.0).abs() < 1e-6);
        assert!(f.retrievability(5.0, 10.0) > f.retrievability(30.0, 10.0));
        assert_eq!(f.retrievability(1.0, 0.0), 0.0);
    }

    #[test]
    fn effective_parameters_match_upstream_constructor() {
        for length in [0, 17, 19, 21] {
            for value in [None, Some(-100.0), Some(100.0), Some(f32::MAX)] {
                let mut configured = fsrs::DEFAULT_PARAMETERS[..length].to_vec();
                if let Some(value) = value {
                    configured.fill(value);
                }
                let Ok(upstream) = fsrs::FSRS::new(&configured) else {
                    assert!(Fsrs::new(&configured, 0.9).is_err());
                    continue;
                };
                let scheduler = Fsrs::new(&configured, 0.9).unwrap();
                // 上游没有公开参数读取接口，回归中用派生 Debug 核对全部实际参数。
                assert_eq!(format!("{upstream:?}"), format!("FSRS {{ parameters: {:?} }}", scheduler.parameters()));
                for rating in [Rating::Again, Rating::Hard, Rating::Good, Rating::Easy] {
                    let expected = upstream.next_states(None, 0.9, 0).unwrap();
                    let expected = match rating {
                        Rating::Again => expected.again,
                        Rating::Hard => expected.hard,
                        Rating::Good => expected.good,
                        Rating::Easy => expected.easy,
                    };
                    let actual = scheduler.review(None, 0.0, rating).unwrap();
                    assert_eq!(actual.memory.stability, expected.memory.stability as f64);
                    assert_eq!(actual.memory.difficulty, expected.memory.difficulty as f64);
                    assert_eq!(actual.interval_days, expected.interval as f64);
                }
                let expected = fsrs::current_retrievability(
                    fsrs::MemoryState { stability: 10.0, difficulty: 5.0 },
                    3.0,
                    scheduler.parameters()[20],
                );
                assert_eq!(scheduler.retrievability(3.0, 10.0), expected as f64);
            }
        }
        let mut configured = fsrs::DEFAULT_PARAMETERS.to_vec();
        configured[4] = 100.0;
        let scheduler = Fsrs::new(&configured, 0.9).unwrap();
        assert_eq!(scheduler.parameters()[4], 10.0);
        assert_eq!(configured[4], 100.0);
    }

    #[test]
    fn package_provenance_matches_locked_dependency() {
        let lock = include_str!("../../../Cargo.lock");
        let package = lock.split("[[package]]").find(|p| p.lines().any(|line| line == "name = \"fsrs\"")).unwrap();
        assert!(package.lines().any(|line| line == format!("version = \"{PACKAGE_VERSION}\"")));
    }

    #[test]
    fn rejects_bad_config() {
        assert!(Fsrs::new(&[], 1.5).is_err());
        assert!(Fsrs::new(&[1.0, 2.0], 0.9).is_err());
    }
}
