-- 交付投影从已发布 intent 定位精确 attempt；不回填历史上传证据。
CREATE INDEX asset_delivery_publication ON asset_upload_intents(tenant_id,published_attempt,asset_id) WHERE published_attempt IS NOT NULL;
