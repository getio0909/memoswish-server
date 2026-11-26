//! 演示数据：首次启动时为本地租户写入四个跨领域卡组（英语词汇 / Rust 编程 / 数理公式与科学 / 中国历史与成语），并合成发音、挂载 BGM。

use memoswish_content::{CardDraft, NewDeck};
use memoswish_core::Principal;
use memoswish_media::{BgmAssignment, SynthesizeOptions};
use memoswish_protocol::{BgmPolicy, CardFace, CardVisual, ContentBlock};
use serde_json::json;

use crate::app::AppState;

fn vocab(deck: &str, word: &str, phonetic: &str, gloss: &str, zh: &str, example: &str) -> CardDraft {
    let mut attributes = serde_json::Map::new();
    attributes.insert("cefr".into(), json!("B2"));
    CardDraft {
        id: None,
        expected_revision: None,
        deck_id: deck.into(),
        template: Some("term".into()),
        language: None,
        front: CardFace {
            title: word.into(),
            subtitle: Some(phonetic.into()),
            blocks: vec![ContentBlock::Text { text: gloss.into() }],
        },
        back: CardFace {
            title: zh.into(),
            subtitle: None,
            blocks: vec![ContentBlock::Quote { text: example.trim_matches('*').into(), source: None }],
        },
        tags: vec!["vocabulary".into()],
        attributes,
        ducking: None,
        visual: None,
    }
}

fn code(deck: &str, q: &str, hint: &str, title: &str, body: &str, src: &str, hl: Vec<u32>) -> CardDraft {
    CardDraft {
        id: None,
        expected_revision: None,
        deck_id: deck.into(),
        template: Some("code".into()),
        language: None,
        front: CardFace::simple(q, hint),
        back: CardFace {
            title: title.into(),
            subtitle: None,
            blocks: vec![
                ContentBlock::Text { text: body.into() },
                ContentBlock::Code { language: "rust".into(), source: src.into(), highlight_lines: hl },
            ],
        },
        tags: vec!["rust".into()],
        attributes: serde_json::Map::new(),
        ducking: None,
        visual: Some(CardVisual { background: "#0B1021".into(), accent: "#25F4EE".into(), image: None }),
    }
}

fn formula(
    deck: &str,
    title: &str,
    field: &str,
    latex: &str,
    prompt: &str,
    explanation: &str,
    bullets: Vec<&str>,
) -> CardDraft {
    let mut attributes = serde_json::Map::new();
    attributes.insert("field".into(), json!(field));
    CardDraft {
        id: None,
        expected_revision: None,
        deck_id: deck.into(),
        template: Some("formula".into()),
        language: None,
        front: CardFace {
            title: title.into(),
            subtitle: Some(field.into()),
            blocks: vec![
                ContentBlock::Math { latex: latex.into(), display: true },
                ContentBlock::Text { text: prompt.into() },
            ],
        },
        back: CardFace {
            title: title.into(),
            subtitle: None,
            blocks: vec![
                ContentBlock::Text { text: explanation.into() },
                ContentBlock::List { items: bullets.into_iter().map(String::from).collect(), ordered: false },
            ],
        },
        tags: vec!["science".into(), field.to_lowercase()],
        attributes,
        ducking: None,
        visual: Some(CardVisual { background: "#0D1B2A".into(), accent: "#4ECDC4".into(), image: None }),
    }
}

fn idiom(deck: &str, word: &str, pinyin: &str, meaning: &str, example: &str) -> CardDraft {
    CardDraft {
        id: None,
        expected_revision: None,
        deck_id: deck.into(),
        template: Some("term".into()),
        language: None,
        front: CardFace { title: word.into(), subtitle: Some(pinyin.into()), blocks: vec![] },
        back: CardFace {
            title: meaning.into(),
            subtitle: None,
            blocks: vec![ContentBlock::Quote { text: example.into(), source: None }],
        },
        tags: vec!["成语".into()],
        attributes: serde_json::Map::new(),
        ducking: None,
        visual: Some(CardVisual { background: "#1A0F0F".into(), accent: "#FFC857".into(), image: None }),
    }
}

/// 没有任何卡组时写入演示数据（仅单用户模式）。
pub async fn seed_if_empty(st: &AppState) -> anyhow::Result<()> {
    if !st.is_single_user() {
        return Ok(());
    }
    let p = Principal::local_owner("seed");
    if !st.services.content.list_decks(&p).await?.is_empty() {
        return Ok(());
    }
    let n = seed(st, &p).await?;
    tracing::info!(target: "memoswish::seed", cards = n, "seeded demo decks");
    Ok(())
}

/// 写入演示卡组，返回卡片数。
pub async fn seed(st: &AppState, p: &Principal) -> anyhow::Result<usize> {
    let content = &st.services.content;
    let media = &st.services.media;

    let en = content
        .create_deck(
            p,
            NewDeck {
                title: "English Vocabulary Starter".into(),
                description: "高频 B2 词汇，刷着刷着就记住。".into(),
                language: "en-US".into(),
                tags: vec!["english".into()],
            },
        )
        .await?;
    let rust = content
        .create_deck(
            p,
            NewDeck {
                title: "Rust in 60 Seconds".into(),
                description: "一张卡一个 Rust 核心概念。".into(),
                language: "en-US".into(),
                tags: vec!["rust".into(), "programming".into()],
            },
        )
        .await?;
    let sci = content
        .create_deck(
            p,
            NewDeck {
                title: "Science & Formulas".into(),
                description: "跨学科核心公式与科学原理（物理、数学、信息论）。".into(),
                language: "en-US".into(),
                tags: vec!["science".into(), "physics".into(), "math".into()],
            },
        )
        .await?;
    let zh = content
        .create_deck(
            p,
            NewDeck {
                title: "中国历史与成语".into(),
                description: "常用成语典故与例句。".into(),
                language: "zh-CN".into(),
                tags: vec!["chinese".into(), "history".into()],
            },
        )
        .await?;

    let decks = vec![
        (
            en.id.clone(),
            "bgm_calm_pad",
            vec![
                vocab(
                    &en.id,
                    "serendipity",
                    "/ˌserənˈdɪpəti/",
                    "Finding something good by chance.",
                    "意外发现美好事物的运气",
                    "*Meeting her was pure serendipity.*",
                ),
                vocab(
                    &en.id,
                    "ubiquitous",
                    "/juːˈbɪkwɪtəs/",
                    "Present everywhere.",
                    "无处不在的",
                    "*Smartphones are ubiquitous today.*",
                ),
                vocab(
                    &en.id,
                    "resilient",
                    "/rɪˈzɪliənt/",
                    "Able to recover quickly.",
                    "有韧性的；能迅速恢复的",
                    "*Kids are remarkably resilient.*",
                ),
                vocab(
                    &en.id,
                    "meticulous",
                    "/məˈtɪkjələs/",
                    "Showing great attention to detail.",
                    "一丝不苟的",
                    "*She keeps meticulous notes.*",
                ),
                vocab(
                    &en.id,
                    "ephemeral",
                    "/ɪˈfemərəl/",
                    "Lasting a very short time.",
                    "短暂的",
                    "*Fame on social media is ephemeral.*",
                ),
                vocab(
                    &en.id,
                    "candid",
                    "/ˈkændɪd/",
                    "Truthful and straightforward.",
                    "坦率的",
                    "*Thanks for your candid feedback.*",
                ),
                vocab(
                    &en.id,
                    "pragmatic",
                    "/præɡˈmætɪk/",
                    "Dealing with things sensibly.",
                    "务实的",
                    "*We need a pragmatic solution.*",
                ),
                vocab(
                    &en.id,
                    "eloquent",
                    "/ˈeləkwənt/",
                    "Fluent and persuasive in speaking.",
                    "雄辩的；有说服力的",
                    "*An eloquent speech moved the crowd.*",
                ),
            ],
        ),
        (
            rust.id.clone(),
            "bgm_focus_pad",
            vec![
                code(
                    &rust.id,
                    "What is ownership?",
                    "Each value has exactly one owner.",
                    "Ownership",
                    "When the owner goes out of scope, the value is dropped.",
                    "let s = String::from(\"hi\");\nlet t = s; // s moved into t\n// println!(\"{s}\"); // error: use after move",
                    vec![2],
                ),
                code(
                    &rust.id,
                    "Borrowing rules?",
                    "Many readers or one writer.",
                    "&T vs &mut T",
                    "Any number of shared references, or exactly one mutable reference.",
                    "let mut v = vec![1];\nlet r = &v;\nprintln!(\"{r:?}\");\nlet m = &mut v;\nm.push(2);",
                    vec![2, 4],
                ),
                code(
                    &rust.id,
                    "What does `?` do?",
                    "Early return on Err / None.",
                    "The ? operator",
                    "Propagates the error to the caller, converting it via From.",
                    "fn read() -> io::Result<String> {\n    let s = fs::read_to_string(\"a.txt\")?;\n    Ok(s)\n}",
                    vec![2],
                ),
                code(
                    &rust.id,
                    "Option vs null?",
                    "Absence is a type, not a crash.",
                    "Option<T>",
                    "Some(value) or None; the compiler forces you to handle both.",
                    "match user.email {\n    Some(e) => send(e),\n    None => skip(),\n}",
                    vec![],
                ),
                code(
                    &rust.id,
                    "What is a trait?",
                    "Shared behavior, like an interface.",
                    "Traits",
                    "Define methods types can implement; enable generics with bounds.",
                    "trait Speak { fn hi(&self) -> String; }\nimpl Speak for Dog {\n    fn hi(&self) -> String { \"woof\".into() }\n}",
                    vec![1],
                ),
            ],
        ),
        (
            sci.id.clone(),
            "bgm_epic_drone",
            vec![
                formula(
                    &sci.id,
                    "Mass-Energy Equivalence",
                    "Physics",
                    "E = mc^2",
                    "How are rest mass and energy related in special relativity?",
                    "Rest mass m is a concentrated form of energy E scaled by the speed of light squared.",
                    vec!["E: rest energy (J)", "m: rest mass (kg)", "c: speed of light in vacuum"],
                ),
                formula(
                    &sci.id,
                    "Bayes' Theorem",
                    "Probability",
                    "P(A\\mid B) = \\frac{P(B\\mid A)\\,P(A)}{P(B)}",
                    "How do you update prior belief P(A) given new evidence B?",
                    "Posterior probability equals likelihood times prior divided by marginal evidence.",
                    vec!["P(A): prior probability", "P(B|A): likelihood", "P(A|B): posterior probability"],
                ),
                formula(
                    &sci.id,
                    "Shannon Entropy",
                    "Information Theory",
                    "H(X) = -\\sum_{x} P(x) \\log_2 P(x)",
                    "What is the average information content of a random variable X?",
                    "Measures uncertainty in bits; uniform distributions maximize entropy.",
                    vec!["Measured in shannons (bits) for base 2", "Equals 0 when outcome is certain"],
                ),
            ],
        ),
        (
            zh.id.clone(),
            "bgm_upbeat_pulse",
            vec![
                idiom(
                    &zh.id,
                    "画蛇添足",
                    "huà shé tiān zú",
                    "做多余的事，反而弄巧成拙",
                    "这句话已经很清楚了，再解释就是画蛇添足。",
                ),
                idiom(
                    &zh.id,
                    "守株待兔",
                    "shǒu zhū dài tù",
                    "死守经验，不知变通；妄想不劳而获",
                    "机会要主动争取，不能守株待兔。",
                ),
                idiom(&zh.id, "井底之蛙", "jǐng dǐ zhī wā", "比喻见识狭窄的人", "多出去走走，别做井底之蛙。"),
                idiom(
                    &zh.id,
                    "亡羊补牢",
                    "wáng yáng bǔ láo",
                    "出了问题及时补救还不算晚",
                    "现在备份数据，亡羊补牢，为时未晚。",
                ),
                idiom(&zh.id, "一鼓作气", "yī gǔ zuò qì", "趁劲头大时一口气完成", "我们一鼓作气把项目做完吧！"),
            ],
        ),
    ];

    let mut total = 0;
    for (deck_id, bgm, drafts) in decks {
        let cards = content.upsert_cards(p, drafts).await?;
        let ids: Vec<String> = cards.iter().map(|c| c.id.clone()).collect();
        for id in ids.iter().filter(|_| media.speech_configured()) {
            // 发音失败（例如外部 TTS 不可用）不阻断启动。
            if let Err(e) = media.synthesize_card(p, id, &SynthesizeOptions::default()).await {
                tracing::warn!(target: "memoswish::seed", card_id = %id, error = %e, "seed tts failed");
            }
        }
        media
            .assign_bgm(
                p,
                &ids,
                &BgmAssignment {
                    expected_revisions: Default::default(),
                    track_id: bgm.into(),
                    policy: BgmPolicy::SwitchOnTheme,
                    theme_key: Some(deck_id.clone()),
                    base_volume: Some(0.6),
                },
            )
            .await?;
        total += ids.len();
    }
    Ok(total)
}
