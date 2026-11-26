//! 视听与发音引擎：
//!
//! - [`tts`]：TTS 引擎实现（`placeholder` 合成音调占位、`command` 调用本地 espeak-ng / piper 等）。
//! - [`segment`]：文本分词与字符区间计算（拉丁语按空白，CJK 按字）。
//! - [`bgm`]：BGM 匹配打分与无版权合成 Pad 生成。
//! - [`service`]：面向 HTTP / MCP 的媒体服务（含缓存、配额、挂载到卡片）。

pub mod bgm;
pub mod segment;
pub mod service;
pub mod tts;
pub mod wav;

pub use service::{BgmAssignment, BgmMatch, BgmQuery, MediaService, SynthesizeOptions};

#[cfg(test)]
mod capacity_regressions;

#[cfg(test)]
mod test_environment {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../scripts/test-environment.rs"));
}
