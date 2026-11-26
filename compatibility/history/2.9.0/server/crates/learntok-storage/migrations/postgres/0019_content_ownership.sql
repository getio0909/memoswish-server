-- 排空所有 writer 后执行；SQLx 将检查、约束、墓碑与历史记账一起提交。
LOCK TABLE tenants, decks, cards IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM decks d WHERE NOT EXISTS(SELECT 1 FROM tenants t WHERE t.id=d.tenant_id)) OR
    EXISTS(SELECT 1 FROM cards c WHERE NOT EXISTS(SELECT 1 FROM decks d WHERE d.tenant_id=c.tenant_id AND d.id=c.deck_id)) THEN
  RAISE EXCEPTION 'content ownership orphan; run learntokd content-orphan-report before migration and repair from verified ownership evidence';
 END IF;
END $$;
ALTER TABLE decks ADD CONSTRAINT decks_owned_tenant FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE cards ADD CONSTRAINT cards_owned_deck FOREIGN KEY(tenant_id,deck_id) REFERENCES decks(tenant_id,id) ON DELETE CASCADE;

-- 墓碑没有个人资料或父外键，租户擦除不能使卡片身份重新可用。
CREATE TABLE deleted_card_ids (tenant_id TEXT NOT NULL, card_id TEXT NOT NULL, PRIMARY KEY(tenant_id,card_id));
INSERT INTO deleted_card_ids
 SELECT tenant_id,card_id FROM memory_states m WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=m.tenant_id AND c.id=m.card_id)
 UNION
 SELECT tenant_id,card_id FROM feedback_events e WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=e.tenant_id AND c.id=e.card_id)
 UNION
 -- S11 快照可能是已删卡片唯一的历史，按回执租户回填最小身份。
 SELECT r.tenant_id,i.value->'card'->>'id' FROM feed_page_receipts r CROSS JOIN LATERAL jsonb_array_elements(r.page::jsonb->'items') i
 WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=r.tenant_id AND c.id=i.value->'card'->>'id');
CREATE FUNCTION protect_content_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  -- API 已持父锁；原生 SQL 也必须序列化删除与身份重用检查。
  PERFORM id FROM tenants WHERE id=OLD.tenant_id FOR UPDATE;
  INSERT INTO deleted_card_ids VALUES(OLD.tenant_id,OLD.id) ON CONFLICT DO NOTHING;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.id<>OLD.id OR NEW.tenant_id<>OLD.tenant_id THEN RAISE EXCEPTION 'content identity is immutable'; END IF;
  RETURN NEW;
 END IF;
 PERFORM id FROM tenants WHERE id=NEW.tenant_id FOR UPDATE;
 -- 唯一索引检查不受事务旧快照限制，不能用 SELECT 墓碑替代。
 -- 先插入再删除本次临时占位；已有永久墓碑会在插入时阻断，绝不进入删除。
 INSERT INTO deleted_card_ids VALUES(NEW.tenant_id,NEW.id);
 DELETE FROM deleted_card_ids WHERE tenant_id=NEW.tenant_id AND card_id=NEW.id;
 RETURN NEW;
END $$;
CREATE TRIGGER cards_identity BEFORE INSERT OR UPDATE OR DELETE ON cards FOR EACH ROW EXECUTE FUNCTION protect_content_identity();
CREATE TRIGGER decks_identity BEFORE UPDATE ON decks FOR EACH ROW EXECUTE FUNCTION protect_content_identity();
