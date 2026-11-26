-- 校验缓存不提供授权；旧资产不自动获得完整验证状态。
CREATE TABLE asset_read_metadata (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL CHECK(length(object_key) BETWEEN 1 AND 512),
    binding TEXT NOT NULL CHECK(length(binding)=64),
    verified INTEGER NOT NULL CHECK(verified IN (0,1)),
    progress INTEGER NOT NULL CHECK(progress BETWEEN 0 AND 1024),
    manifest TEXT NOT NULL CHECK(length(manifest)<=75000),
    PRIMARY KEY(tenant_id,object_key)
);
