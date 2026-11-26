//! 冷恢复演练通过既有 ignored 集成入口运行，外部工具缺失必须失败。

#![cfg(feature = "sqlite")]

#[test]
#[ignore = "integration: requires node, sqlite3, strip, flock, GNU mv and the real memoswishd binary"]
fn embedded_cold_recovery_rehearsal() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let status = std::process::Command::new("node")
        .current_dir(root)
        .args(["--test", "scripts/backup-embedded.test.mjs"])
        .env("MEMOSWISH_RECOVERY_BINARY", env!("CARGO_BIN_EXE_memoswishd"))
        .status()
        .expect("node is required for the embedded recovery rehearsal");
    assert!(status.success(), "embedded recovery rehearsal failed: {status}");
}
