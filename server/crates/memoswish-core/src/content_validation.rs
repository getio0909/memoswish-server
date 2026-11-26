//! 卡片写入校验：保证下发给客户端的数据满足不变量。

use crate::{CoreError, CoreResult};
use memoswish_protocol::{Card, ContentBlock, TtsTrack};

/// 标题最大字符数。
pub const MAX_TITLE_CHARS: usize = 200;
/// 副标题最大字符数。
pub const MAX_SUBTITLE_CHARS: usize = 200;
/// 单个内容块最大字符数。
pub const MAX_BLOCK_CHARS: usize = 8_000;
/// 单面最大内容块数量。
pub const MAX_BLOCKS_PER_FACE: usize = 32;
/// 模板标识最大字符数。
pub const MAX_TEMPLATE_CHARS: usize = 64;

fn is_hex_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

/// 校验整张卡片。
pub fn validate_card(card: &Card) -> CoreResult<()> {
    for asset in crate::assets::card_assets(card) {
        crate::assets::validate_asset_ref(asset)?;
    }
    if card.deck_id.trim().is_empty() {
        return Err(CoreError::invalid("deck_id is required"));
    }
    if card.language.trim().is_empty() {
        return Err(CoreError::invalid("language is required"));
    }
    if card.template.trim().is_empty() || card.template.chars().count() > MAX_TEMPLATE_CHARS {
        return Err(CoreError::invalid(format!("template must be non-empty and at most {MAX_TEMPLATE_CHARS} chars")));
    }
    for (name, face) in [("front", &card.front), ("back", &card.back)] {
        if name == "front" && face.title.trim().is_empty() {
            return Err(CoreError::invalid("front.title is required"));
        }
        if face.title.chars().count() > MAX_TITLE_CHARS {
            return Err(CoreError::invalid(format!("{name}.title exceeds {MAX_TITLE_CHARS} chars")));
        }
        if let Some(sub) = &face.subtitle
            && sub.chars().count() > MAX_SUBTITLE_CHARS
        {
            return Err(CoreError::invalid(format!("{name}.subtitle exceeds {MAX_SUBTITLE_CHARS} chars")));
        }
        if face.blocks.len() > MAX_BLOCKS_PER_FACE {
            return Err(CoreError::invalid(format!("{name}.blocks exceeds {MAX_BLOCKS_PER_FACE} items")));
        }
        for (i, block) in face.blocks.iter().enumerate() {
            validate_block(name, i, block)?;
        }
    }
    card.ducking.validate().map_err(CoreError::invalid)?;
    if !is_hex_color(&card.visual.background) || !is_hex_color(&card.visual.accent) {
        return Err(CoreError::invalid("visual colors must be #RRGGBB"));
    }
    if let Some(bgm) = &card.bgm {
        if let Some(p) = &bgm.track.provenance {
            crate::content_lifecycle::validate_provenance(p)?;
        }
        if bgm.track.pcm.is_some() {
            crate::bgm::validate_track_metadata(&bgm.track)?;
        }
    }
    if let Some(bgm) = &card.bgm
        && !(0.0..=1.0).contains(&bgm.base_volume)
    {
        return Err(CoreError::invalid("bgm.base_volume must be within [0, 1]"));
    }
    if let Some(tts) = &card.tts {
        validate_tts(tts)?;
    }
    Ok(())
}

fn validate_block(face_name: &str, idx: usize, block: &ContentBlock) -> CoreResult<()> {
    match block {
        ContentBlock::Text { text } => {
            if text.chars().count() > MAX_BLOCK_CHARS {
                return Err(CoreError::invalid(format!(
                    "{face_name}.blocks[{idx}] text exceeds {MAX_BLOCK_CHARS} chars"
                )));
            }
        }
        ContentBlock::Code { source, .. } => {
            if source.chars().count() > MAX_BLOCK_CHARS {
                return Err(CoreError::invalid(format!(
                    "{face_name}.blocks[{idx}] code exceeds {MAX_BLOCK_CHARS} chars"
                )));
            }
        }
        ContentBlock::Math { latex, .. } => {
            if latex.trim().is_empty() || latex.chars().count() > MAX_BLOCK_CHARS {
                return Err(CoreError::invalid(format!(
                    "{face_name}.blocks[{idx}] math latex must be non-empty and <= {MAX_BLOCK_CHARS} chars"
                )));
            }
        }
        ContentBlock::Quote { text, .. } => {
            if text.chars().count() > MAX_BLOCK_CHARS {
                return Err(CoreError::invalid(format!(
                    "{face_name}.blocks[{idx}] quote exceeds {MAX_BLOCK_CHARS} chars"
                )));
            }
        }
        ContentBlock::List { items, .. } => {
            if items.len() > 100 {
                return Err(CoreError::invalid(format!("{face_name}.blocks[{idx}] list exceeds 100 items")));
            }
        }
        ContentBlock::Table { header, rows } => {
            if header.len() > 20 || rows.len() > 100 {
                return Err(CoreError::invalid(format!("{face_name}.blocks[{idx}] table exceeds maximum dimensions")));
            }
        }
        ContentBlock::Link { url, .. } => {
            if url.trim().is_empty() {
                return Err(CoreError::invalid(format!("{face_name}.blocks[{idx}] link url is required")));
            }
        }
        ContentBlock::Image { asset, .. } => crate::assets::validate_asset_ref(asset)?,
    }
    Ok(())
}

/// 校验 TTS 音轨的逐词时间戳。
pub fn validate_tts(tts: &TtsTrack) -> CoreResult<()> {
    if let Some(p) = &tts.provenance {
        crate::content_lifecycle::validate_provenance(p)?;
    }
    let text_len = tts.text.chars().count() as u32;
    let mut prev_end = 0u32;
    for (i, w) in tts.words.iter().enumerate() {
        if w.end_ms < w.start_ms {
            return Err(CoreError::invalid(format!("words[{i}]: end_ms < start_ms")));
        }
        if w.start_ms < prev_end {
            return Err(CoreError::invalid(format!("words[{i}]: overlaps previous word")));
        }
        if w.end_ms > tts.duration_ms {
            return Err(CoreError::invalid(format!("words[{i}]: end_ms exceeds duration_ms")));
        }
        if w.char_end < w.char_start || w.char_end > text_len {
            return Err(CoreError::invalid(format!("words[{i}]: invalid char range")));
        }
        prev_end = w.end_ms;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_protocol::examples;

    #[test]
    fn sample_cards_are_valid() {
        validate_card(&examples::sample_card()).unwrap();
        validate_card(&examples::sample_rich_card()).unwrap();
    }

    #[test]
    fn rejects_bad_cards() {
        let mut c = examples::sample_card();
        c.front.title = " ".into();
        assert!(validate_card(&c).is_err());

        let mut c = examples::sample_card();
        c.visual.accent = "red".into();
        assert!(validate_card(&c).is_err());

        let mut c = examples::sample_card();
        let tts = c.tts.as_mut().unwrap();
        tts.words[1].start_ms = 100;
        assert!(validate_card(&c).is_err());
    }
}
