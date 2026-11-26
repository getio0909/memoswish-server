-- SQLite 的 oauth_registry 写锁和普通写事务已互斥，无需 PostgreSQL 的父行锁。
-- 保留对等迁移编号；既有墓碑触发器在串行写入后拒绝晚到数据。
SELECT 1;
