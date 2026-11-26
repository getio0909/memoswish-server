//! 便携封套的有界校验及到既有 S18 工作的映射，不执行外部读取。
use base64::{Engine, engine::general_purpose::STANDARD};
use memoswish_core::{CoreError, CoreResult, Permission, Principal, assets::*, imports::*};
use memoswish_protocol::{PortableDeckPack, PortableMedia};
use std::collections::{HashMap, HashSet};

pub const CARDS: usize = 500;
pub const BLOBS: usize = 4096;
pub const CONTENT_BYTES: usize = IMPORT_CONTENT_BYTES;
pub const MEDIA_BYTES: usize = 8 * 1024 * 1024;
pub const DOCUMENT_BYTES: usize = 12 * 1024 * 1024;

/// 只计数序列化输出；超限时停止，不创建第二份无界 JSON 缓冲。
pub fn bounded_json(value: &impl serde::Serialize, limit: usize) -> CoreResult<()> {
    json_bytes(value, limit).map(|_| ())
}

pub fn blob_asset(m: &PortableMedia) -> memoswish_protocol::AssetRef {
    memoswish_protocol::AssetRef {
        key: m.id.clone(),
        url: String::new(),
        mime: m.mime.clone(),
        bytes: m.bytes,
        sha256: m.sha256.clone(),
    }
}

/// 所有闭包、摘要和元数据验证先于任何持久准入或 PUT。
pub fn validate(pack: &PortableDeckPack) -> CoreResult<Vec<ImportMedia>> {
    validate_input(&input_value(&pack)?).map(|(_, media)| media)
}

/// 输入正文及便携封套都在解码补默认值之前按原始 JSON 值计量。
pub fn validate_input(wire: &serde_json::Value) -> CoreResult<(PortableDeckPack, Vec<ImportMedia>)> {
    let budget = crate::processing::WorkBudget::default();
    input_json_bytes(wire, DOCUMENT_BYTES)?;
    input_json_bytes(&wire["content"], CONTENT_BYTES)?;
    let pack: PortableDeckPack =
        serde_json::from_value(wire.clone()).map_err(|_| CoreError::invalid("invalid portable DeckPack input"))?;
    if !((pack.version == "2.0" && pack.content.version == "1.0")
        || (pack.version == "2.1" && pack.content.version == "1.1")
        || (pack.version == "2.2" && pack.content.version == "1.2"))
    {
        return Err(CoreError::Unsupported("unsupported portable DeckPack version".into()));
    }
    if pack.version != "2.2" && pack.content.cards.iter().any(memoswish_core::bgm::has_media_metadata) {
        return Err(CoreError::Unsupported("media metadata requires portable DeckPack 2.2".into()));
    }
    if pack.content.cards.len() > CARDS
        || pack.media.len() > BLOBS
        || pack.content.deck.card_count as usize != pack.content.cards.len()
    {
        return Err(CoreError::invalid("portable DeckPack count exceeds bounds or disagrees"));
    }
    let deck = &pack.content.deck;
    if deck.title.trim().is_empty()
        || deck.title.trim().chars().count() > 200
        || deck.language.trim().is_empty()
        || deck.language.len() > 64
    {
        return Err(CoreError::invalid("invalid portable deck metadata"));
    }
    let mut decoded = Vec::new();
    let mut ids = HashMap::new();
    let mut identities = HashSet::new();
    let mut total = 0usize;
    for m in &pack.media {
        budget.charge(m.data_base64.len())?;
        validate_asset_id(&m.id)?;
        validate_asset_ref(&blob_asset(m))?;
        if ids.insert(m.id.as_str(), m).is_some() {
            return Err(CoreError::invalid("duplicate portable media id"));
        }
        if !identities.insert((&m.mime, &m.sha256, m.bytes)) {
            return Err(CoreError::invalid("duplicate portable blob identity"));
        }
        let size = usize::try_from(m.bytes).map_err(|_| CoreError::invalid("invalid portable media size"))?;
        total = total
            .checked_add(size)
            .filter(|v| *v <= MEDIA_BYTES)
            .ok_or_else(|| CoreError::invalid("portable media exceeds 8 MiB"))?;
        // 在解码分配前检验长度；STANDARD 拒绝非规范填充和尾部非零位。
        if m.data_base64.len() != size.div_ceil(3) * 4 {
            return Err(CoreError::invalid("portable base64 length mismatch"));
        }
        let bytes =
            STANDARD.decode(&m.data_base64).map_err(|_| CoreError::invalid("invalid canonical portable base64"))?;
        if bytes.len() != size || memoswish_core::ids::sha256_hex(&bytes) != m.sha256 {
            return Err(CoreError::invalid("portable media integrity mismatch"));
        }
        decoded.push(ImportMedia { asset: blob_asset(m), bytes });
    }
    let mut used = HashSet::new();
    let mut cards = HashSet::new();
    for card in &pack.content.cards {
        budget.charge(1)?;
        memoswish_core::content_validation::validate_card(card)?;
        if card.deck_id != pack.content.deck.id || !cards.insert(&card.id) {
            return Err(CoreError::invalid("portable card identity mismatch"));
        }
        for asset in card_assets(card) {
            let m = ids.get(asset.key.as_str()).ok_or_else(|| CoreError::invalid("missing portable media"))?;
            if !asset.url.is_empty() || asset.mime != m.mime || asset.sha256 != m.sha256 || asset.bytes != m.bytes {
                return Err(CoreError::invalid("portable attachment metadata mismatch"));
            }
            used.insert(asset.key.as_str());
        }
    }
    if used.len() != ids.len() {
        return Err(CoreError::invalid("unused portable media"));
    }
    Ok((pack, decoded))
}

impl crate::ContentService {
    pub fn prepare_portable_deck_pack(&self, p: &Principal, pack: impl serde::Serialize) -> CoreResult<ImportWork> {
        p.require(Permission::ContentWrite)?;
        let mut wire = input_value(&pack)?;
        let (pack, mut media) = validate_input(&wire)?;
        if !media.is_empty() {
            p.require(Permission::MediaWrite)?;
        }
        let source_bytes = input_json_bytes(&wire["content"]["cards"], CONTENT_BYTES)?;
        let tracks: Vec<_> = pack.content.cards.iter().map(|c| (c.tts.clone(), c.bgm.clone())).collect();
        let mut work = self.prepare_deck_pack(p, wire["content"].take(), false)?;
        let prefix = format!("{}portable/{}/", p.asset_prefix(), work.deck.id);
        for m in &mut media {
            m.asset.key = format!("{prefix}{}", m.asset.key);
        }
        let mut track_ids = HashMap::new();
        for (card, (tts, bgm)) in work.cards.iter_mut().zip(tracks) {
            card.tts = tts;
            card.bgm = bgm;
            if let Some(bgm) = &mut card.bgm {
                bgm.track.id =
                    track_ids.entry(bgm.track.id.clone()).or_insert_with(memoswish_core::ids::new_id).clone();
            }
            for (_, asset) in card_asset_slots_mut(card) {
                asset.key = format!("{prefix}{}", asset.key);
                asset.url.clear();
            }
            memoswish_core::content_validation::validate_card(card)?;
        }
        work.media = media;
        let normalized_bytes = json_bytes(&work.cards, PORTABLE_SNAPSHOT_BYTES)?;
        work.identity_expansion_bytes = normalized_bytes.saturating_sub(source_bytes + work.provenance_expansion_bytes);
        work.cards_byte_limit()?;
        Ok(work)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> PortableDeckPack {
        memoswish_protocol::examples::sample_portable_deck_pack()
    }
    #[test]
    fn portable_closure_and_canonical_base64_reject_damage() {
        assert_eq!(validate(&sample()).unwrap().len(), 2);
        type Mutation = Box<dyn Fn(&mut PortableDeckPack)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|p| p.media.clear()),
            Box::new(|p| p.media.push(p.media[0].clone())),
            Box::new(|p| {
                let mut m = p.media[0].clone();
                m.id = "duplicate".into();
                p.content.cards[0].visual.image.as_mut().unwrap().key = m.id.clone();
                p.media.push(m);
            }),
            Box::new(|p| {
                let mut m = p.media[0].clone();
                m.id = "unused".into();
                p.media.push(m);
            }),
            Box::new(|p| p.media[0].sha256 = "0".repeat(64)),
            Box::new(|p| p.media[0].bytes = u64::MAX),
            Box::new(|p| {
                p.media[0].data_base64 = "YR==".into();
                p.media[0].bytes = 1;
            }),
            Box::new(|p| p.media[0].data_base64 = "YWJj=".into()),
            Box::new(|p| p.media[0].data_base64 = "____".into()),
            Box::new(|p| p.media[0].data_base64 = "YW J".into()),
            Box::new(|p| p.media[0].id = "../escape".into()),
            Box::new(|p| {
                p.content.cards[0].visual.image.as_mut().unwrap().url = "https://example.invalid/secret".into()
            }),
            Box::new(|p| p.content.cards[0].visual.image.as_mut().unwrap().key = "tenants/foreign/uploads/fake".into()),
            Box::new(|p| p.content.cards[0].visual.image.as_mut().unwrap().mime = "video/mp4".into()),
            Box::new(|p| p.version = "3.0".into()),
        ];
        for mutate in mutations {
            let mut pack = sample();
            mutate(&mut pack);
            assert!(validate(&pack).is_err());
        }
        assert!(
            serde_json::from_value::<memoswish_protocol::DeckPack>(serde_json::to_value(sample()).unwrap()).is_err()
        );
        assert!(
            serde_json::from_value::<memoswish_protocol::PortableImportRequest>(
                serde_json::json!({"pack":sample(),"auto_tts":true})
            )
            .is_err()
        );
    }
    #[test]
    fn portable_limits_are_exact_and_checked_before_decode() {
        bounded_json(&"abc", 5).unwrap();
        assert!(bounded_json(&"abc", 4).is_err());
        let mut pack = sample();
        pack.media[0].data_base64 = "A".repeat(MEDIA_BYTES.div_ceil(3) * 4 + 4);
        assert!(validate(&pack).is_err());
        let mut pack = sample();
        pack.content.cards = vec![pack.content.cards[0].clone(); CARDS + 1];
        pack.content.deck.card_count = (CARDS + 1) as u32;
        assert!(validate(&pack).is_err());
        let mut pack = sample();
        pack.media = vec![pack.media[0].clone(); BLOBS + 1];
        assert!(validate(&pack).is_err());
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn portable_exact_media_and_card_limits() {
        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        pack.media.truncate(1);
        let data = vec![0; MEDIA_BYTES];
        let m = &mut pack.media[0];
        m.bytes = data.len() as u64;
        m.sha256 = memoswish_core::ids::sha256_hex(&data);
        m.data_base64 = STANDARD.encode(&data);
        let asset = blob_asset(m);
        for c in &mut pack.content.cards {
            for (_, a) in card_asset_slots_mut(c) {
                *a = asset.clone();
            }
        }
        assert_eq!(validate(&pack).unwrap()[0].bytes.len(), MEDIA_BYTES);
        let m = &mut pack.media[0];
        m.bytes += 1;
        m.data_base64 = STANDARD.encode(vec![0; MEDIA_BYTES + 1]);
        assert!(validate(&pack).is_err());
        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        let card = pack.content.cards[0].clone();
        pack.content.cards = (0..CARDS)
            .map(|i| {
                let mut c = card.clone();
                c.id = format!("c{i}");
                c
            })
            .collect();
        pack.content.deck.card_count = CARDS as u32;
        validate(&pack).unwrap();
        pack.content.cards.push(card);
        pack.content.deck.card_count += 1;
        assert!(validate(&pack).is_err());
        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        pack.content.cards.clear();
        pack.content.deck.card_count = 0;
        pack.media.clear();
        validate(&pack).unwrap();
    }
}

#[cfg(test)]
mod combined_boundary_tests {
    use super::*;
    #[test]
    fn portable_exact_blob_content_and_document_budgets() {
        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        pack.media.clear();
        pack.content.cards.clear();
        for group in 0..BLOBS / 64 {
            let mut card = memoswish_protocol::examples::sample_card();
            card.id = format!("card{group}");
            card.deck_id = pack.content.deck.id.clone();
            card.tts = None;
            card.bgm = None;
            card.visual.image = None;
            card.front.blocks.clear();
            card.back.blocks.clear();
            for i in 0..64 {
                let index = group * 64 + i;
                let bytes = (index as u32).to_le_bytes();
                let m = PortableMedia {
                    id: format!("m{index}"),
                    mime: "image/png".into(),
                    bytes: 4,
                    sha256: memoswish_core::ids::sha256_hex(&bytes),
                    data_base64: STANDARD.encode(bytes),
                };
                let block = memoswish_protocol::ContentBlock::Image { asset: blob_asset(&m), alt: String::new() };
                if i < 32 {
                    card.front.blocks.push(block);
                } else {
                    card.back.blocks.push(block);
                }
                pack.media.push(m);
            }
            pack.content.cards.push(card);
        }
        pack.content.deck.card_count = pack.content.cards.len() as u32;
        assert_eq!(validate(&pack).unwrap().len(), BLOBS);
        pack.media.push(pack.media[0].clone());
        assert!(validate(&pack).is_err());

        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        pack.media.clear();
        pack.content.cards.clear();
        pack.content.deck.card_count = 0;
        pack.content.deck.description.clear();
        let current = serde_json::to_vec(&pack.content).unwrap().len();
        pack.content.deck.description = "x".repeat(CONTENT_BYTES - current);
        assert_eq!(serde_json::to_vec(&pack.content).unwrap().len(), CONTENT_BYTES);
        validate(&pack).unwrap();
        pack.content.deck.description.push('x');
        assert!(validate(&pack).is_err());

        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        pack.media.truncate(1);
        let bytes = vec![0; MEDIA_BYTES];
        let m = &mut pack.media[0];
        m.bytes = MEDIA_BYTES as u64;
        m.sha256 = memoswish_core::ids::sha256_hex(&bytes);
        m.data_base64 = STANDARD.encode(bytes);
        let a = blob_asset(m);
        for c in &mut pack.content.cards {
            for (_, asset) in card_asset_slots_mut(c) {
                *asset = a.clone();
            }
        }
        pack.content.deck.description.clear();
        let current = serde_json::to_vec(&pack).unwrap().len();
        pack.content.deck.description = "x".repeat(DOCUMENT_BYTES - current);
        assert_eq!(serde_json::to_vec(&pack).unwrap().len(), DOCUMENT_BYTES);
        validate(&pack).unwrap();
        pack.content.deck.description.push('x');
        assert!(validate(&pack).is_err());
    }
}

#[cfg(test)]
mod canonical_tests {
    use super::*;
    #[test]
    fn portable_base64_rejects_nonzero_trailing_bits_even_when_digest_matches() {
        let mut pack = memoswish_protocol::examples::sample_portable_deck_pack();
        let m = &mut pack.media[0];
        m.bytes = 1;
        m.sha256 = memoswish_core::ids::sha256_hex(b"a");
        m.data_base64 = "YQ==".into();
        let asset = blob_asset(m);
        for c in &mut pack.content.cards {
            for (_, a) in card_asset_slots_mut(c) {
                if a.key == asset.key {
                    *a = asset.clone();
                }
            }
        }
        validate(&pack).unwrap();
        pack.media[0].data_base64 = "YR==".into();
        assert!(validate(&pack).is_err());
        pack.media[0].data_base64 = "YQ".into();
        assert!(validate(&pack).is_err());
    }
}
