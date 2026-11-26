//! 可复现的轻量随机数（SplitMix64）。同一 `(session_id, slot)` 总是得到相同的随机序列，便于调试与测试。

use sha2::{Digest, Sha256};

/// SplitMix64 生成器。
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// 以字符串与序号派生种子。
    pub fn from_parts(key: &str, n: u64) -> Self {
        let digest = Sha256::digest(format!("{key}#{n}").as_bytes());
        let mut b = [0u8; 8];
        b.copy_from_slice(&digest[..8]);
        Self(u64::from_le_bytes(b))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// [0, 1) 均匀分布。
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// [0, n) 均匀整数；n 为 0 时返回 0。
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_bounded() {
        let mut a = SplitMix64::from_parts("s", 1);
        let mut b = SplitMix64::from_parts("s", 1);
        for _ in 0..100 {
            let x = a.next_f64();
            assert_eq!(x, b.next_f64());
            assert!((0.0..1.0).contains(&x));
        }
        assert!(SplitMix64::new(1).below(3) < 3);
    }
}
