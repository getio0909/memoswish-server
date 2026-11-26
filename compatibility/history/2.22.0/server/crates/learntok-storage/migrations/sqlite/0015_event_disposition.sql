-- 历史事件不补造策略来源；新接受凭据与事件及投影原子提交。
ALTER TABLE feedback_events ADD COLUMN application_provenance TEXT;
