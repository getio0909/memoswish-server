//! 在仓储短事务的当前快照上应用内容变更，两个后端共用相同的版本和合并规则。

use chrono::{DateTime, Utc};
use memoswish_protocol::{BgmBinding, Card, CardDraft, DEFAULT_TEMPLATE, Deck, TtsTrack};

use crate::content_validation::validate_card;
use crate::{CoreError, CoreResult};

/// 每批目标唯一，创建与更新由草稿原始 ID 是否存在区分。
#[derive(Debug, Clone)]
pub enum CardMutation {
    Draft { id: String, draft: CardDraft },
    Author { id: String, save: Box<memoswish_protocol::CardSave>, observed_generation: Option<String> },
    Publication { id: String, command: memoswish_protocol::PublicationCommand },
    Tts { id: String, expected_revision: u32, track: TtsTrack },
    Bgm { id: String, expected_revision: Option<u32>, binding: Option<BgmBinding> },
}

impl CardMutation {
    pub fn id(&self) -> &str {
        match self {
            Self::Author { id, .. }
            | Self::Publication { id, .. }
            | Self::Draft { id, .. }
            | Self::Tts { id, .. }
            | Self::Bgm { id, .. } => id,
        }
    }

    pub fn apply(&self, current: Option<Card>, deck: Option<&Deck>, now: DateTime<Utc>) -> CoreResult<Card> {
        let mut card = match self {
            Self::Author { id, save, observed_generation } => {
                let observed_generation = observed_generation.clone().or_else(|| {
                    current.as_ref().and_then(|c| c.content.as_ref().and_then(|m| m.observed_generation.clone()))
                });
                crate::content_lifecycle::validate_save(save)?;
                let provenance = save
                    .provenance
                    .clone()
                    .or_else(|| current.as_ref().and_then(|c| c.content.as_ref().map(|m| m.provenance.clone())))
                    .unwrap_or_default();
                let mut c = Self::Draft { id: id.clone(), draft: save.card.clone() }.apply(current, deck, now)?;
                c.content = Some(memoswish_protocol::ContentMetadata {
                    observed_generation,
                    publication: if save.publish { "published" } else { "draft" }.into(),
                    provenance,
                });
                c
            }
            Self::Publication { id, command } => {
                let mut c = required(current, id)?;
                c.revision = next_revision(Some(command.expected_revision), c.revision)?;
                let metadata = c.content.get_or_insert(memoswish_protocol::ContentMetadata {
                    observed_generation: None,
                    publication: "published".into(),
                    provenance: Default::default(),
                });
                metadata.publication = if command.publish { "published" } else { "draft" }.into();
                c
            }
            Self::Draft { id, draft } => {
                let deck = deck.ok_or_else(|| CoreError::NotFound(format!("deck `{}`", draft.deck_id)))?;
                if draft.id.is_none() {
                    if draft.expected_revision.is_some() {
                        return Err(CoreError::invalid("expected_revision requires an existing card id"));
                    }
                    if current.is_some() {
                        return Err(CoreError::Conflict(format!("card `{id}` already exists")));
                    }
                } else if draft.id.as_deref() != Some(id) {
                    return Err(CoreError::invalid("card mutation id does not match draft"));
                }
                let old = if draft.id.is_some() { Some(required(current, id)?) } else { None };
                let language = draft.language.clone().unwrap_or_else(|| deck.language.clone());
                let revision = match &old {
                    Some(c) => next_revision(draft.expected_revision, c.revision)?,
                    None => 1,
                };
                let mut c = old.unwrap_or_else(|| Card {
                    content: None,
                    id: id.clone(),
                    deck_id: deck.id.clone(),
                    template: DEFAULT_TEMPLATE.into(),
                    language: language.clone(),
                    front: draft.front.clone(),
                    back: draft.back.clone(),
                    tags: vec![],
                    attributes: Default::default(),
                    tts: None,
                    bgm: None,
                    ducking: Default::default(),
                    visual: Default::default(),
                    revision: 1,
                    created_at: now,
                    updated_at: now,
                });
                if c.front != draft.front || c.back != draft.back || c.language != language {
                    c.tts = None;
                }
                c.deck_id = draft.deck_id.clone();
                c.language = language;
                c.front = draft.front.clone();
                c.back = draft.back.clone();
                c.tags = draft.tags.clone();
                if let Some(template) = &draft.template {
                    c.template = template.clone();
                }
                if !draft.attributes.is_empty() {
                    c.attributes = draft.attributes.clone();
                }
                if let Some(ducking) = &draft.ducking {
                    c.ducking = *ducking;
                }
                if let Some(visual) = &draft.visual {
                    c.visual = visual.clone();
                }
                c.revision = revision;
                c
            }
            Self::Tts { id, expected_revision, track } => {
                let mut c = required(current, id)?;
                c.revision = next_revision(Some(*expected_revision), c.revision)?;
                c.tts = Some(track.clone());
                c
            }
            Self::Bgm { id, expected_revision, binding } => {
                let mut c = required(current, id)?;
                c.revision = next_revision(*expected_revision, c.revision)?;
                c.bgm = binding.clone();
                c
            }
        };
        card.updated_at = now;
        validate_card(&card)?;
        Ok(card)
    }
}

fn required(card: Option<Card>, id: &str) -> CoreResult<Card> {
    card.ok_or_else(|| CoreError::NotFound(format!("card `{id}`")))
}

/// 缺省版本允许兼容写入，显式版本必须与事务内当前版本一致。
pub fn next_revision(expected: Option<u32>, current: u32) -> CoreResult<u32> {
    check_revision(expected, current)?;
    current.checked_add(1).ok_or_else(|| CoreError::Conflict(format!("revision exhausted; current revision {current}")))
}

pub fn check_revision(expected: Option<u32>, current: u32) -> CoreResult<()> {
    if expected == Some(0) {
        return Err(CoreError::invalid("expected_revision must be positive"));
    }
    if expected.is_some_and(|value| value != current) {
        return Err(CoreError::Conflict(format!("revision mismatch; current revision {current}")));
    }
    Ok(())
}
