//! OSS PostgreSQL 安装恢复通过集成层运行，缺工具、数据库或建库权限时失败。

#![cfg(feature = "postgres")]

#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL with CREATEDB, node, pg_dump/pg_restore, strip, flock and GNU mv"]
fn postgres_cold_recovery_rehearsal() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let status = std::process::Command::new("node")
        .current_dir(root)
        .args(["--test", "scripts/backup-embedded-postgres.test.mjs"])
        .env("MEMOSWISH_RECOVERY_BINARY", env!("CARGO_BIN_EXE_memoswishd"))
        .status()
        .expect("node is required for the PostgreSQL recovery rehearsal");
    assert!(status.success(), "PostgreSQL recovery rehearsal failed: {status}");
}
