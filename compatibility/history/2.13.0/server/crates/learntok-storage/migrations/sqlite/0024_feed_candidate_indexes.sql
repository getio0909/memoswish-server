-- 完整候选元数据按租户及可选卡组稳定遍历，避免读取正文和排序临时树。
CREATE INDEX idx_cards_feed_global ON cards(tenant_id, created_at, id);
CREATE INDEX idx_cards_feed_deck ON cards(tenant_id, deck_id, created_at, id);
-- 重点库使用字面谓词以匹配部分索引，历史无活卡的记忆仍保留。
CREATE INDEX idx_memory_feed_starred ON memory_states(tenant_id, user_id, card_id) WHERE starred;
