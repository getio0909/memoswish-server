//! 学习资料库：卡组 / 卡片 CRUD、写入校验、原始资料切片、内容包导入导出与 AI 深度解析。

pub mod apkg;
pub mod explain;
pub mod imports;
pub mod service;
pub mod slicer;
pub mod validate;

pub use explain::{AiExplainConfig, explain_card};
pub use service::{CardDraft, ContentService, NewDeck};
pub use slicer::slice_material;

pub mod deckpack;

mod lifecycle;
pub mod starter;

pub mod processing;
