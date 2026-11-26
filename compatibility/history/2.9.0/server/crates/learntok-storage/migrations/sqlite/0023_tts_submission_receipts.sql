-- 历史 S16 请求者仍为手动挂载；只有新提交项进入自动恢复。
ALTER TABLE tts_requesters ADD COLUMN credential_via TEXT NOT NULL DEFAULT 'legacy';
CREATE TABLE tts_submissions (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, request_id TEXT NOT NULL,
 command_hash TEXT NOT NULL, account_generation BIGINT NOT NULL, membership_generation BIGINT NOT NULL,
 PRIMARY KEY(tenant_id,user_id,request_id)
);
-- 不引用业务父对象，删除卡片、成员或租户不能级联抹去未完成责任。
CREATE TABLE tts_submission_items (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, request_id TEXT NOT NULL,
 position BIGINT NOT NULL CHECK(position>=0 AND position<100), item_id TEXT NOT NULL,
 receipt TEXT CHECK(receipt IS NULL OR json_valid(receipt)),
 PRIMARY KEY(tenant_id,item_id), UNIQUE(tenant_id,user_id,request_id,position),
 FOREIGN KEY(tenant_id,user_id,request_id) REFERENCES tts_submissions(tenant_id,user_id,request_id) ON DELETE RESTRICT,
 FOREIGN KEY(tenant_id,item_id) REFERENCES tts_requesters(tenant_id,id) ON DELETE RESTRICT
);
CREATE INDEX tts_submission_pending ON tts_submission_items(tenant_id,item_id) WHERE receipt IS NULL;
