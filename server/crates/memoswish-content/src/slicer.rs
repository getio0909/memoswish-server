//! 原始资料切片：把跨领域的半结构化文本拆成卡片草稿，供 MCP `material_slice` 工具预览或直接入库。
//!
//! 支持的格式（逐行识别，可混用）：
//! - `term :: definition`、`term - definition`、`term — definition`、`term<TAB>definition` → 词条卡（`template = "term"`）
//! - `Q: ...` 紧跟 `A: ...` → 问答卡（`template = "qa"`）
//! - Markdown `## 标题` + 后续段落（可含 ``` 代码块、$$ 公式块）→ 概念 / 代码 / 公式卡
//!
//! 复杂资料建议由 AI Agent 自行切片后调用 `card_upsert`，本切片器提供确定性、零外部依赖的结构化拆解。

use memoswish_protocol::{CardFace, ContentBlock};

use crate::service::CardDraft;

fn draft(deck_id: &str, template: &str, front: CardFace, back: CardFace) -> CardDraft {
    CardDraft {
        id: None,
        expected_revision: None,
        deck_id: deck_id.into(),
        template: Some(template.into()),
        language: None,
        front,
        back,
        tags: vec![],
        attributes: serde_json::Map::new(),
        ducking: None,
        visual: None,
    }
}

fn split_pair(line: &str) -> Option<(&str, &str)> {
    for sep in [" :: ", "\t", " — ", " - "] {
        if let Some((a, b)) = line.split_once(sep)
            && !a.trim().is_empty()
            && !b.trim().is_empty()
        {
            return Some((a, b));
        }
    }
    None
}

/// 将资料切片为卡片草稿（最多 `max_cards` 张）。
pub fn slice_material(deck_id: &str, text: &str, max_cards: usize) -> Vec<CardDraft> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(raw) = lines.next() {
        if out.len() >= max_cards {
            break;
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Markdown 小节。
        if let Some(title) = line.strip_prefix("## ").or_else(|| line.strip_prefix("# ")) {
            let mut body = Vec::new();
            let mut extra_blocks: Vec<ContentBlock> = Vec::new();
            let mut has_code = false;
            let mut has_math = false;
            while let Some(next) = lines.peek() {
                if next.trim_start().starts_with('#') {
                    break;
                }
                let next = lines.next().unwrap_or_default();
                if let Some(lang) = next.trim().strip_prefix("```") {
                    let mut src = Vec::new();
                    for l in lines.by_ref() {
                        if l.trim() == "```" {
                            break;
                        }
                        src.push(l);
                    }
                    has_code = true;
                    extra_blocks.push(ContentBlock::Code {
                        language: if lang.trim().is_empty() { "text".into() } else { lang.trim().into() },
                        source: src.join("\n"),
                        highlight_lines: vec![],
                    });
                } else if next.trim() == "$$" {
                    let mut latex = Vec::new();
                    for l in lines.by_ref() {
                        if l.trim() == "$$" {
                            break;
                        }
                        latex.push(l);
                    }
                    has_math = true;
                    extra_blocks.push(ContentBlock::Math { latex: latex.join("\n"), display: true });
                } else {
                    body.push(next);
                }
            }
            let body = body.join("\n");
            let (summary, rest) = match body.trim().split_once("\n\n") {
                Some((a, b)) => (a.to_string(), b.to_string()),
                None => (String::new(), body.trim().to_string()),
            };
            let template = if has_code {
                "code"
            } else if has_math {
                "formula"
            } else {
                "concept"
            };
            let front = CardFace::simple(title.trim(), summary.trim());
            let mut back = CardFace::simple(title.trim(), rest.trim());
            back.blocks.extend(extra_blocks);
            out.push(draft(deck_id, template, front, back));
            continue;
        }
        // 问答对。
        if let Some(q) = line.strip_prefix("Q:").or_else(|| line.strip_prefix("Q：")) {
            let answer = lines
                .peek()
                .and_then(|n| n.trim().strip_prefix("A:").or_else(|| n.trim().strip_prefix("A：")))
                .map(str::to_string);
            if let Some(a) = answer {
                lines.next();
                out.push(draft(deck_id, "qa", CardFace::simple(q.trim(), ""), CardFace::simple(a.trim(), "")));
                continue;
            }
        }
        // 词条对。
        if let Some((term, def)) = split_pair(line) {
            out.push(draft(deck_id, "term", CardFace::simple(term.trim(), ""), CardFace::simple(def.trim(), "")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_mixed_material() {
        let text = "serendipity :: 意外发现美好事物\nubiquitous - 无处不在的\n\nQ: 2+2?\nA: 4\n\n## Borrowing\nReferences without ownership.\n\nYou can have many `&T` or one `&mut T`.\n```rust\nlet r = &x;\n```\n## Euler Identity\nA jewel of mathematics.\n$$\ne^{i\\pi} + 1 = 0\n$$\n## Lifetimes\nScopes of references.";
        let cards = slice_material("d1", text, 50);
        assert_eq!(cards.len(), 6);
        assert_eq!(cards[0].template.as_deref(), Some("term"));
        assert_eq!(cards[0].front.title, "serendipity");
        assert_eq!(cards[1].back.title, "无处不在的");
        assert_eq!(cards[2].template.as_deref(), Some("qa"));
        assert_eq!(cards[3].template.as_deref(), Some("code"));
        assert_eq!(cards[3].front.primary_text(), "References without ownership.");
        assert!(
            cards[3].back.blocks.iter().any(|b| matches!(b, ContentBlock::Code { language, .. } if language == "rust"))
        );
        assert_eq!(cards[4].template.as_deref(), Some("formula"));
        assert!(cards[4].back.blocks.iter().any(|b| matches!(b, ContentBlock::Math { display: true, .. })));
        assert_eq!(cards[5].template.as_deref(), Some("concept"));
        assert_eq!(slice_material("d1", text, 2).len(), 2);
    }
}
