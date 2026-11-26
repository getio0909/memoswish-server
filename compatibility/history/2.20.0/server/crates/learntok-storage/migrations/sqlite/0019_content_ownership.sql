-- 迁移前须备份并排空 writer；孤儿不能通过捏造归属自动修复。
CREATE TABLE s14_preflight (value INTEGER);
CREATE TRIGGER s14_preflight_check BEFORE INSERT ON s14_preflight BEGIN
 SELECT CASE WHEN
  EXISTS(SELECT 1 FROM decks d WHERE NOT EXISTS(SELECT 1 FROM tenants t WHERE t.id=d.tenant_id)) OR
  EXISTS(SELECT 1 FROM cards c WHERE NOT EXISTS(SELECT 1 FROM decks d WHERE d.tenant_id=c.tenant_id AND d.id=c.deck_id))
 THEN RAISE(ABORT,'content ownership orphan; run learntokd content-orphan-report before migration and repair from verified ownership evidence') END;
END;
INSERT INTO s14_preflight VALUES(1);
DROP TABLE s14_preflight;

-- 复制原始列而不解码历史 JSON；外键始终启用，旧表先删子表再删父表。
CREATE TABLE decks_owned (
 id TEXT NOT NULL, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', language TEXT NOT NULL,
 tags TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,id)
);
CREATE TABLE cards_owned (
 id TEXT NOT NULL, tenant_id TEXT NOT NULL, deck_id TEXT NOT NULL, template TEXT NOT NULL,
 revision INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,deck_id) REFERENCES decks_owned(tenant_id,id) ON DELETE CASCADE
);
INSERT INTO decks_owned SELECT * FROM decks;
INSERT INTO cards_owned SELECT * FROM cards;
DROP TABLE cards;
DROP TABLE decks;
ALTER TABLE decks_owned RENAME TO decks;
ALTER TABLE cards_owned RENAME TO cards;
CREATE INDEX idx_cards_deck ON cards(tenant_id,deck_id,created_at);
CREATE TRIGGER erased_decks_insert BEFORE INSERT ON decks WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_decks_update BEFORE UPDATE ON decks WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_cards_insert BEFORE INSERT ON cards WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;
CREATE TRIGGER erased_cards_update BEFORE UPDATE ON cards WHEN EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=NEW.tenant_id) BEGIN SELECT RAISE(ABORT,'tenant erased'); END;

-- 墓碑仅保留随机租户和卡片 ID，不含学习或个人资料，也不依赖租户存活。
CREATE TABLE deleted_card_ids (tenant_id TEXT NOT NULL, card_id TEXT NOT NULL, PRIMARY KEY(tenant_id,card_id));
INSERT INTO deleted_card_ids
 SELECT tenant_id,card_id FROM memory_states m WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=m.tenant_id AND c.id=m.card_id)
 UNION
 SELECT tenant_id,card_id FROM feedback_events e WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=e.tenant_id AND c.id=e.card_id)
 UNION
 -- S11 快照可能是已删卡片唯一的历史，按回执租户回填最小身份。
 SELECT r.tenant_id,json_extract(i.value,'$.card.id') FROM feed_page_receipts r,json_each(r.page,'$.items') i
 WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=r.tenant_id AND c.id=json_extract(i.value,'$.card.id'));
CREATE TRIGGER cards_remember_delete AFTER DELETE ON cards BEGIN
 INSERT INTO deleted_card_ids VALUES(OLD.tenant_id,OLD.id) ON CONFLICT DO NOTHING;
END;
CREATE TRIGGER cards_reject_reuse BEFORE INSERT ON cards WHEN EXISTS(SELECT 1 FROM deleted_card_ids WHERE tenant_id=NEW.tenant_id AND card_id=NEW.id) BEGIN SELECT RAISE(ABORT,'card ID was deleted; import with a new ID'); END;
CREATE TRIGGER cards_identity_immutable BEFORE UPDATE ON cards WHEN NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id BEGIN SELECT RAISE(ABORT,'card identity is immutable'); END;
CREATE TRIGGER decks_identity_immutable BEFORE UPDATE ON decks WHEN NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id BEGIN SELECT RAISE(ABORT,'deck identity is immutable'); END;

-- SQLx 在同一事务内执行；用约束将外键检查结果转为提交失败。
CREATE TABLE s14_fk_check (violations INTEGER CHECK(violations=0));
INSERT INTO s14_fk_check SELECT COUNT(*) FROM pragma_foreign_key_check;
DROP TABLE s14_fk_check;
