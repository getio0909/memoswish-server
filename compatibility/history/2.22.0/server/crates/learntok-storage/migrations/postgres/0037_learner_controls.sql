-- 学习偏好与发卡序列独立于记忆；成员删除按范围级联清理。
CREATE TABLE learner_preferences (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
 desired_retention DOUBLE PRECISION CHECK(desired_retention >= 0.50 AND desired_retention <= 0.99),
 revision BIGINT NOT NULL DEFAULT 0 CHECK(revision>=0),
 epoch BIGINT NOT NULL DEFAULT 0 CHECK(epoch>=0),
 issuance_seq BIGINT NOT NULL DEFAULT 0 CHECK(issuance_seq>=0),
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
-- 隐藏从不创建或重置 FSRS 记忆；发卡排序与控制修订分别递增。
CREATE TABLE learner_card_controls (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, card_id TEXT NOT NULL,
 suspended BIGINT NOT NULL DEFAULT 0 CHECK(suspended IN (0,1)),
 buried_until_ms BIGINT,
 revision BIGINT NOT NULL DEFAULT 0 CHECK(revision>=0),
 last_issued_seq BIGINT NOT NULL DEFAULT 0 CHECK(last_issued_seq>=0),
 PRIMARY KEY(tenant_id,user_id,card_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,card_id) REFERENCES cards(tenant_id,id) ON DELETE CASCADE,
 CHECK(suspended=0 OR buried_until_ms IS NULL)
);
CREATE INDEX learner_controls_hidden ON learner_card_controls(tenant_id,user_id,suspended,buried_until_ms,card_id);
