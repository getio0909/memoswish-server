//! 成瘾性信息流引擎：
//!
//! 1. [`signals`]：把无感行为埋点解释为 FSRS 评分 + 标星。
//! 2. [`fsrs`]：FSRS-5 记忆模型（稳定性 / 难度 / 可提取率）。
//! 3. [`engine`]：按“到期 / 新卡 / 强化 / 惊喜”四个桶 + 可变奖赏随机调度生成无限信息流与预加载清单。

mod candidates;
mod coordinator;
pub mod engine;
pub mod fsrs;
mod learning_policy;
pub mod rng;
pub mod signals;

pub use engine::{FeedConfig, FeedService, LearningStats};
pub use fsrs::{Fsrs, Rating};
pub use signals::{Outcome, SignalPolicy};

mod controls;

#[cfg(test)]
mod test_environment {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/test-environment.rs"));
}
