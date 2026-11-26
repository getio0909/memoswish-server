// 测试工具读取新变量前检查旧名称，避免缺前提时静默跳过或改用默认值。
pub fn var(key: &str) -> Result<String, std::env::VarError> {
    reject_legacy_environment();
    std::env::var(key)
}

pub fn reject_legacy_environment() {
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if let Some(suffix) = key.strip_prefix("LEARNTOK_") {
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                panic!("Legacy environment variable LEARNTOK_{suffix} is unsupported. Use MEMOSWISH_{suffix}.");
            }
            panic!("Legacy LEARNTOK_* environment variables are unsupported. Use MEMOSWISH_* replacements.");
        }
    }
}
