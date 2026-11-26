-- 私有内容状态只从当前正文派生，旧行缺省发布，不重写旧主体或投递回执。
ALTER TABLE decks ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK(revision > 0 AND revision <= 4294967295);
ALTER TABLE cards ADD COLUMN publication TEXT GENERATED ALWAYS AS (COALESCE(body->'content'->>'publication', 'published')) STORED;
CREATE INDEX cards_publication ON cards(tenant_id, publication, deck_id, created_at, id);

CREATE TABLE content_revisions (
    tenant_id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK(revision > 0),
    body JSONB NOT NULL,
    PRIMARY KEY(tenant_id, card_id, revision),
    FOREIGN KEY(tenant_id, card_id) REFERENCES cards(tenant_id, id) ON DELETE CASCADE
);
-- 仅记录升级时确实存在的修订，不补造缺失历史。
INSERT INTO content_revisions(tenant_id,card_id,revision,body) SELECT tenant_id,id,revision,body FROM cards;

CREATE TABLE content_reports (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    card_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    corrected_revision BIGINT,
    body JSONB NOT NULL,
    PRIMARY KEY(tenant_id,id),
    FOREIGN KEY(tenant_id,card_id) REFERENCES cards(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id,user_id) REFERENCES tenant_memberships(tenant_id,user_id) ON DELETE CASCADE
);
CREATE INDEX content_reports_card ON content_reports(tenant_id,card_id,corrected_revision,id);
CREATE FUNCTION content_revision_archive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO content_revisions(tenant_id,card_id,revision,body) VALUES(NEW.tenant_id,NEW.id,NEW.revision,NEW.body) ON CONFLICT DO NOTHING;
    RETURN NEW;
END $$;
CREATE TRIGGER content_revision_archive AFTER INSERT OR UPDATE ON cards FOR EACH ROW EXECUTE FUNCTION content_revision_archive();
