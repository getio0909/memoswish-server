//! 带版本和 key ID 的 AEAD；旧密文仅使用显式 legacy key，未知 key 永不回退。
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use memoswish_core::{CoreError, CoreResult};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone)]
pub struct EnvelopeKeys {
    active: String,
    keys: BTreeMap<String, (Arc<Aes256Gcm>, Option<i64>)>,
    legacy: Option<(Arc<Aes256Gcm>, Option<i64>)>,
}
fn error() -> CoreError {
    CoreError::Unauthorized("invalid encrypted envelope".into())
}
fn cipher(secret: &str) -> CoreResult<Arc<Aes256Gcm>> {
    let bytes = URL_SAFE_NO_PAD.decode(secret).map_err(|_| CoreError::invalid("encryption key must be base64url"))?;
    Ok(Arc::new(
        Aes256Gcm::new_from_slice(&bytes).map_err(|_| CoreError::invalid("encryption key must contain 32 bytes"))?,
    ))
}
impl EnvelopeKeys {
    pub fn new(
        active: &str,
        keys: &BTreeMap<String, crate::token::VerificationKey>,
        legacy: Option<&str>,
        legacy_until: Option<i64>,
    ) -> CoreResult<Self> {
        if active.is_empty()
            || keys.keys().any(|k| {
                k.is_empty() || k.len() > 64 || !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            })
        {
            return Err(CoreError::invalid("invalid encryption key id"));
        }
        let keys = keys
            .iter()
            .map(|(id, k)| Ok((id.clone(), (cipher(&k.secret)?, k.verify_until))))
            .collect::<CoreResult<BTreeMap<_, _>>>()?;
        let current = keys.get(active).ok_or_else(|| CoreError::invalid("active encryption key is missing"))?;
        if current.1.is_some() {
            return Err(CoreError::invalid("active encryption key cannot have a retirement bound"));
        }
        Ok(Self {
            active: active.into(),
            keys,
            legacy: legacy.map(|s| cipher(s).map(|k| (k, legacy_until))).transpose()?,
        })
    }
    pub fn seal(&self, text: &str, context: &str) -> CoreResult<String> {
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| CoreError::internal("OS randomness unavailable"))?;
        let aad = format!("learntok-aead-v1\0{}\0{context}", self.active);
        let data = self.keys[&self.active]
            .0
            .encrypt((&nonce).into(), Payload { msg: text.as_bytes(), aad: aad.as_bytes() })
            .map_err(|_| error())?;
        Ok(format!("v1.{}.{}", self.active, URL_SAFE_NO_PAD.encode([nonce.to_vec(), data].concat())))
    }
    pub fn is_active(&self, text: &str) -> bool {
        text.starts_with(&format!("v1.{}.", self.active))
    }
    pub fn open(&self, text: &str, context: &str) -> CoreResult<String> {
        let (key, until, payload, aad) = if text.starts_with("v1.") {
            let mut parts = text.split('.');
            parts.next();
            let id = parts.next().ok_or_else(error)?;
            let payload = parts.next().ok_or_else(error)?;
            if parts.next().is_some() {
                return Err(error());
            }
            let (key, until) = self.keys.get(id).ok_or_else(error)?;
            (key, until, payload, format!("learntok-aead-v1\0{id}\0{context}"))
        } else {
            let (key, until) = self.legacy.as_ref().ok_or_else(error)?;
            (key, until, text, context.into())
        };
        if until.is_some_and(|t| chrono::Utc::now().timestamp() >= t) {
            return Err(error());
        }
        let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| error())?;
        if bytes.len() < 28 {
            return Err(error());
        }
        let plain =
            key.decrypt(bytes[..12].into(), Payload { msg: &bytes[12..], aad: aad.as_bytes() }).map_err(|_| error())?;
        String::from_utf8(plain).map_err(|_| error())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decrypt_old_encrypt_new_restart_context_and_retirement() {
        let key = |b| crate::token::VerificationKey { secret: URL_SAFE_NO_PAD.encode([b; 32]), verify_until: None };
        let mut keys = BTreeMap::from([("old".into(), key(1))]);
        let old = EnvelopeKeys::new("old", &keys, None, None).unwrap().seal("sentinel-secret", "attempt:one").unwrap();
        keys.insert("new".into(), key(2));
        let rotated = EnvelopeKeys::new("new", &keys, None, None).unwrap();
        assert_eq!(rotated.open(&old, "attempt:one").unwrap(), "sentinel-secret");
        assert!(rotated.seal("value", "attempt:one").unwrap().starts_with("v1.new."));
        assert!(rotated.open(&old, "pending-link").is_err());
        let (prefix, payload) = old.rsplit_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        bytes[12] ^= 1;
        assert!(rotated.open(&format!("{prefix}.{}", URL_SAFE_NO_PAD.encode(bytes)), "attempt:one").is_err());
        let nonce = [7; 12];
        let legacy_cipher = cipher(&URL_SAFE_NO_PAD.encode([3; 32])).unwrap();
        let encrypted =
            legacy_cipher.encrypt((&nonce).into(), Payload { msg: b"legacy-value", aad: b"context" }).unwrap();
        let unversioned = URL_SAFE_NO_PAD.encode([nonce.to_vec(), encrypted].concat());
        let legacy = URL_SAFE_NO_PAD.encode([3; 32]);
        let migrated = EnvelopeKeys::new("new", &keys, Some(&legacy), None).unwrap();
        assert_eq!(migrated.open(&unversioned, "context").unwrap(), "legacy-value");
        assert!(
            EnvelopeKeys::new("new", &keys, Some(&legacy), Some(0)).unwrap().open(&unversioned, "context").is_err()
        );
        assert!(rotated.open(&old.replace("v1.old.", "v1.unknown."), "attempt:one").is_err());
        keys.get_mut("old").unwrap().verify_until = Some(0);
        assert!(EnvelopeKeys::new("new", &keys, None, None).unwrap().open(&old, "attempt:one").is_err());
        assert!(!format!("{:?}", key(1)).contains(&URL_SAFE_NO_PAD.encode([1; 32])));
    }
}
