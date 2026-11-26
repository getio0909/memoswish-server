//! ID 生成与内容哈希工具。

use sha2::{Digest, Sha256};

/// 单用户自托管模式下的固定租户 ID。
pub const LOCAL_TENANT_ID: &str = "local";
/// 单用户自托管模式下的固定用户 ID。
pub const LOCAL_USER_ID: &str = "usr_local";

/// 生成按时间有序的新 ID（UUID v7）。
pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// 计算内容的 SHA-256（小写十六进制）。
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_sortable() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert!(a < b);
    }

    #[test]
    fn sha_is_stable() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
