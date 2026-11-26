//! 自有教学内容；选择安装才复制到当前工作区。
use memoswish_protocol::*;
pub fn catalog() -> Vec<StarterDeck> {
    vec![StarterDeck {
        id: "learning-basics-v1".into(),
        title: "从三张卡开始".into(),
        description: "主动回忆、间隔复习与小步学习。选择后加入当前工作区。".into(),
        attribution: "Memoswish contributors".into(),
        rights: "Apache-2.0".into(),
    }]
}
pub fn pack(id: &str) -> memoswish_core::CoreResult<DeckPack> {
    let starter = catalog()
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| memoswish_core::CoreError::NotFound("starter".into()))?;
    let now = chrono::DateTime::from_timestamp(0, 0).expect("epoch");
    let deck = Deck {
        revision: Some(1),
        id: starter.id.clone(),
        title: starter.title,
        description: starter.description,
        language: "zh-CN".into(),
        tags: vec!["学习方法".into()],
        card_count: 3,
        created_at: now,
    };
    let cards = [
        ("主动回忆是什么？", "先尝试自己回答，再翻面核对；答错也是发现知识缺口的机会。"),
        ("为什么把复习分散到多天？", "间隔复习让你在需要回忆时再次练习；不必把所有重复挤在同一次学习里。"),
        ("怎样开始一个小主题？", "写一个具体问题和一个清楚答案，先学一张，再逐步扩展。"),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (front, back))| Card {
        content: Some(ContentMetadata {
            observed_generation: None,
            publication: "published".into(),
            provenance: ContentProvenance {
                method: "starter".into(),
                // 已发布安装包的署名参与回执指纹，保持旧版字节。
                attribution: "LearnTok contributors".into(),
                rights: starter.rights.clone(),
                ..Default::default()
            },
        }),
        id: format!("starter-{i}"),
        deck_id: deck.id.clone(),
        template: "basic".into(),
        language: deck.language.clone(),
        front: CardFace::simple(front, ""),
        back: CardFace::simple(back, ""),
        tags: vec![],
        attributes: Default::default(),
        tts: None,
        bgm: None,
        ducking: Default::default(),
        visual: Default::default(),
        revision: 1,
        created_at: now,
        updated_at: now,
    })
    .collect();
    Ok(DeckPack { version: "1.0".into(), deck, cards, exported_at: now })
}
